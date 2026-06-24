//! The host's **held-set**: the authoritative record of which CIDs this pinning host has committed
//! to keep, with the per-CID accounting needed for capacity management, garbage collection, expiry
//! enforcement, and rent.
//!
//! This is the host's own ground truth. The proof-of-retrievability audit gates on it (a host may
//! only answer a challenge for a CID it locally committed to — see [`crate::host`]), so it must be
//! durable and corruption-resistant: it is persisted with an atomic temp-file + rename, and a
//! corrupt file is backed up and surfaced (not silently dropped, which would erase every paid
//! commitment on one bad write).
//!
//! Money note: `rent_per_gb_hour` is a **base-unit decimal string** (1 credit = 10^18 base units),
//! never a float — consistent with the SDK wire form.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Schema version of the on-disk held-set, so future shapes can migrate rather than be misread.
pub const HELD_SCHEMA_VERSION: u32 = 1;

/// Per-CID commitment record: everything the host needs to bill, expire, and evict a pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldEntry {
    /// Object size in bytes (from the successful fetch — the real held size, not the declared one).
    pub bytes: u64,
    /// Rent the publisher agreed to pay, base units per GB-hour (decimal string).
    #[serde(default)]
    pub rent_per_gb_hour: String,
    /// Block height after which rent is no longer guaranteed; `0` means "no expiry / open-ended".
    #[serde(default)]
    pub expiry_height: u64,
    /// Unix seconds when the pin was accepted (LRU base and rent-accrual start).
    #[serde(default)]
    pub pinned_at: u64,
    /// Unix seconds of the last access (offer re-accept, status, or audit) — the LRU recency key.
    #[serde(default)]
    pub last_access: u64,
    /// NodeId hex of the publisher that requested the pin (for accounting/attribution).
    #[serde(default)]
    pub publisher: String,
}

impl HeldEntry {
    /// Rent rate parsed to base units (0 if the stored string is absent or malformed).
    pub fn rent_base(&self) -> u128 {
        self.rent_per_gb_hour.trim().parse().unwrap_or(0)
    }
}

/// The set of CIDs this host holds, keyed by CID (BTreeMap → stable, diff-friendly persistence).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldSet {
    /// Schema discriminator; defaulted so a v0 (bare `{cids:[...]}`) file is detected on load.
    #[serde(default)]
    pub version: u32,
    /// CID → commitment record.
    #[serde(default)]
    pub entries: BTreeMap<String, HeldEntry>,
}

impl HeldSet {
    /// Whether this CID is currently committed (the audit gate and `pin/status` consult this).
    pub fn contains(&self, cid: &str) -> bool {
        self.entries.contains_key(cid)
    }

    /// The number of held CIDs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if nothing is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total bytes held across all commitments — the figure capacity admission checks against.
    pub fn total_bytes(&self) -> u64 {
        self.entries.values().map(|e| e.bytes).fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Record (or refresh) a commitment for `cid`. Idempotent: re-offering an already-held CID just
    /// updates its size/terms and bumps `last_access`.
    pub fn insert(&mut self, cid: String, entry: HeldEntry) {
        self.entries.insert(cid, entry);
    }

    /// Mark a held CID as accessed `now`, refreshing its LRU recency. No-op if not held.
    pub fn touch(&mut self, cid: &str, now: u64) {
        if let Some(e) = self.entries.get_mut(cid) {
            e.last_access = now;
        }
    }

    /// Drop a commitment, returning the bytes it freed (0 if it was not held).
    pub fn remove(&mut self, cid: &str) -> u64 {
        self.entries.remove(cid).map(|e| e.bytes).unwrap_or(0)
    }

    /// The CIDs whose `expiry_height` is non-zero and `<= current_height` — past their rent lease.
    /// A host drops these in GC and stops advertising them.
    pub fn expired(&self, current_height: u64) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| e.expiry_height != 0 && e.expiry_height <= current_height)
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Choose CIDs to evict so that, after dropping them, the held total is at or below
    /// `target_bytes`. Eviction priority (worst-kept first): **expired** before live; then **lowest
    /// rent** (least valuable to keep); then **least-recently accessed** (LRU); then CID for a
    /// deterministic, testable tiebreak. Pure: it does not mutate the set — the caller removes the
    /// returned CIDs. `current_height` classifies expiry. Returns the CIDs to evict, in eviction
    /// order; if the set already fits, returns empty.
    pub fn evict_to_fit(&self, target_bytes: u64, current_height: u64) -> Vec<String> {
        let total = self.total_bytes();
        if total <= target_bytes {
            return Vec::new();
        }
        let mut need_to_free = total - target_bytes;
        // Build a ranking key per entry; sort ascending so the *first* entries are the ones we evict.
        let mut ranked: Vec<(&String, &HeldEntry)> = self.entries.iter().collect();
        ranked.sort_by(|(a_cid, a), (b_cid, b)| {
            let a_expired = a.expiry_height != 0 && a.expiry_height <= current_height;
            let b_expired = b.expiry_height != 0 && b.expiry_height <= current_height;
            // Expired first (true sorts before false here): invert the bool comparison.
            b_expired
                .cmp(&a_expired)
                .then(a.rent_base().cmp(&b.rent_base())) // lowest rent first
                .then(a.last_access.cmp(&b.last_access)) // least-recently used first
                .then(a_cid.cmp(b_cid)) // deterministic tiebreak
        });
        let mut victims = Vec::new();
        for (cid, e) in ranked {
            if need_to_free == 0 {
                break;
            }
            victims.push(cid.clone());
            need_to_free = need_to_free.saturating_sub(e.bytes);
        }
        victims
    }

    /// Load the held-set from `path`. A missing file is an empty set. A **corrupt** file is NOT
    /// silently discarded (that would erase every paid commitment on a single bad write): it is moved
    /// aside to `<path>.corrupt` and the error is surfaced so the operator notices. A legacy v0 file
    /// (the old `{ "cids": ["..."] }` shape) is migrated forward, preserving the CIDs with zeroed
    /// accounting (the host re-learns sizes on the next status/audit).
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HeldSet::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        // Try the current schema first.
        if let Ok(mut set) = serde_json::from_slice::<HeldSet>(&bytes) {
            // A v0 file deserializes here too (version defaults to 0, entries empty) — detect and
            // migrate from the legacy `cids` array if present.
            if set.version == 0 && set.entries.is_empty() {
                if let Ok(legacy) = serde_json::from_slice::<LegacyHeldSet>(&bytes) {
                    if !legacy.cids.is_empty() {
                        for cid in legacy.cids {
                            set.entries.insert(cid, HeldEntry::default_record());
                        }
                    }
                }
            }
            set.version = HELD_SCHEMA_VERSION;
            return Ok(set);
        }
        // Unparseable: preserve it for forensics rather than dropping commitments.
        let aside = path.with_extension("corrupt");
        let _ = std::fs::rename(path, &aside);
        Err(anyhow::anyhow!(
            "held-set at {} was corrupt; moved aside to {} (no commitments were silently dropped)",
            path.display(),
            aside.display()
        ))
    }

    /// Persist atomically: write to a temp file in the same directory, fsync it, then rename over the
    /// target (rename is atomic on the same filesystem), so a crash mid-write can never leave a
    /// truncated `held.json`. Returns after the data is durably in place.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        atomic_write(path, &json)
    }
}

impl HeldEntry {
    /// A record for a freshly-discovered CID with no known accounting (used by the v0 migration).
    fn default_record() -> Self {
        HeldEntry {
            bytes: 0,
            rent_per_gb_hour: String::new(),
            expiry_height: 0,
            pinned_at: 0,
            last_access: 0,
            publisher: String::new(),
        }
    }
}

/// The legacy v0 on-disk shape (`{ "cids": ["..."] }`), read only during migration.
#[derive(Deserialize)]
struct LegacyHeldSet {
    #[serde(default)]
    cids: Vec<String>,
}

/// Atomically write `bytes` to `path` via a temp file + fsync + rename. Shared by held-set and
/// pin-set persistence so both are crash-safe.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // A unique temp name in the same dir keeps the rename atomic and avoids cross-process clobber.
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("held"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        f.write_all(bytes).with_context(|| format!("writing {}", tmp.display()))?;
        f.flush().ok();
        // Best-effort fsync: durability before the rename. Ignored if the platform/FS rejects it.
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path).with_context(|| {
        // Clean up the temp file on a failed rename so we do not leak it.
        let _ = std::fs::remove_file(&tmp);
        format!("renaming {} -> {}", tmp.display(), path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(bytes: u64, rent: &str, expiry: u64, last_access: u64) -> HeldEntry {
        HeldEntry {
            bytes,
            rent_per_gb_hour: rent.to_string(),
            expiry_height: expiry,
            pinned_at: 0,
            last_access,
            publisher: String::new(),
        }
    }

    #[test]
    fn total_bytes_sums_entries() {
        let mut h = HeldSet::default();
        h.insert("a".into(), entry(100, "0", 0, 0));
        h.insert("b".into(), entry(250, "0", 0, 0));
        assert_eq!(h.total_bytes(), 350);
    }

    #[test]
    fn expired_lists_only_past_lease() {
        let mut h = HeldSet::default();
        h.insert("live".into(), entry(1, "0", 100, 0));
        h.insert("gone".into(), entry(1, "0", 50, 0));
        h.insert("openended".into(), entry(1, "0", 0, 0)); // 0 = never expires
        let mut exp = h.expired(60);
        exp.sort();
        assert_eq!(exp, vec!["gone".to_string()]);
    }

    #[test]
    fn evict_prefers_expired_then_low_rent_then_lru() {
        let mut h = HeldSet::default();
        // total = 400; target 150 -> need to free 250.
        h.insert("expired".into(), entry(100, "9999", 10, 999)); // expired: evicted first despite high rent + recent
        h.insert("cheap".into(), entry(100, "1", 0, 100)); // lowest rent among live
        h.insert("old".into(), entry(100, "5", 0, 1)); // higher rent but LRU
        h.insert("keep".into(), entry(100, "5", 0, 999)); // higher rent, recently used -> kept
        let victims = h.evict_to_fit(150, 60);
        // Need 250 freed: expired(100) + cheap(100) + old(100=300) -> three victims, "keep" survives.
        assert_eq!(victims.len(), 3);
        assert_eq!(victims[0], "expired", "expired must be evicted first");
        assert!(!victims.contains(&"keep".to_string()), "highest-value recent pin must survive");
    }

    #[test]
    fn evict_noop_when_under_target() {
        let mut h = HeldSet::default();
        h.insert("a".into(), entry(100, "0", 0, 0));
        assert!(h.evict_to_fit(1000, 0).is_empty());
    }

    #[test]
    fn atomic_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ce-pin-held-{}", std::process::id()));
        let path = dir.join("held.json");
        let mut h = HeldSet::default();
        h.insert("cid-z".into(), entry(512, "1000", 8640, 7));
        h.save(&path).unwrap();
        let back = HeldSet::load(&path).unwrap();
        assert_eq!(back.version, HELD_SCHEMA_VERSION);
        assert_eq!(back.entries.get("cid-z").unwrap().bytes, 512);
        assert_eq!(back.entries.get("cid-z").unwrap().expiry_height, 8640);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_is_preserved_not_dropped() {
        let dir = std::env::temp_dir().join(format!("ce-pin-held-corrupt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("held.json");
        std::fs::write(&path, b"{ truncated not json").unwrap();
        let res = HeldSet::load(&path);
        assert!(res.is_err(), "a corrupt held-set must surface an error, not silently default");
        // The bad file was moved aside, not deleted.
        assert!(path.with_extension("corrupt").exists(), "corrupt file must be preserved for forensics");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_v0_file_migrates_forward() {
        let dir = std::env::temp_dir().join(format!("ce-pin-held-v0-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("held.json");
        // The old shape: a bare cids array.
        std::fs::write(&path, br#"{ "cids": ["legacy-a", "legacy-b"] }"#).unwrap();
        let set = HeldSet::load(&path).unwrap();
        assert_eq!(set.version, HELD_SCHEMA_VERSION);
        assert!(set.contains("legacy-a") && set.contains("legacy-b"), "v0 CIDs must migrate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_updates_recency() {
        let mut h = HeldSet::default();
        h.insert("c".into(), entry(1, "0", 0, 5));
        h.touch("c", 99);
        assert_eq!(h.entries.get("c").unwrap().last_access, 99);
    }
}
