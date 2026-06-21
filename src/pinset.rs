//! The pin-set: the client-side index of what this node has published and where it is replicated.
//!
//! Persisted as JSON at `<config dir>/ce-pin/pins.json` (human-inspectable; small). Each entry pairs
//! the immutable [`PinJob`] (the content + desired replication + rent terms) with the live
//! [`Replica`] set (which hosts currently hold it and their last audit result). The CLI reads/writes
//! this file; the audit/re-replication loop updates the replica health in place.
//!
//! Money note: `rent_per_gb_hour` is stored as a **base-unit decimal string** (1 credit = 10^18
//! base units), never a float — consistent with how the SDK carries amounts on the wire.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// An immutable description of a published, pinned object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinJob {
    /// The object CID (manifest hash from `put_object`).
    pub cid: String,
    /// Total object size in bytes.
    pub bytes_len: u64,
    /// Desired number of live replicas. The audit loop re-pins to restore this if holders drop.
    pub replication: u8,
    /// Rent offered, base units per GB-hour (decimal string; never a float).
    pub rent_per_gb_hour: String,
    /// Block height after which rent is no longer guaranteed.
    pub expiry_height: u64,
    /// Optional human label for `ce-pin ls`.
    #[serde(default)]
    pub label: Option<String>,
}

/// A single replica: a host that accepted the pin, plus its last-known health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replica {
    /// 64-hex NodeId of the holder.
    pub holder: String,
    /// Payment channel id opened to pay this holder rent (empty if rent not yet wired up).
    #[serde(default)]
    pub channel_id: String,
    /// Result of the most recent proof-of-retrievability audit (`true` = proof verified).
    #[serde(default)]
    pub last_proof_ok: bool,
}

/// One pin-set entry: the job plus its current replica set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub job: PinJob,
    #[serde(default)]
    pub replicas: Vec<Replica>,
}

impl Entry {
    /// Count of replicas whose last audit passed (the live replication factor).
    pub fn healthy_replicas(&self) -> usize {
        self.replicas.iter().filter(|r| r.last_proof_ok).count()
    }
}

/// The whole pin-set, keyed by CID (a `BTreeMap` so `ls` output is stable and the file diffs cleanly).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinSet {
    #[serde(default)]
    pub pins: BTreeMap<String, Entry>,
}

impl PinSet {
    /// Default on-disk location: `<config dir>/ce-pin/pins.json`, overridable via `$CE_PIN_DIR`.
    pub fn default_path() -> PathBuf {
        if let Some(d) = std::env::var_os("CE_PIN_DIR") {
            return PathBuf::from(d).join("pins.json");
        }
        let base = directories::ProjectDirs::from("", "", "ce-pin")
            .map(|p| p.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".ce-pin"));
        base.join("pins.json")
    }

    /// Load the pin-set from `path`, returning an empty set if the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PinSet::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Persist the pin-set to `path`, creating parent directories as needed. Written
    /// pretty-printed so a human can inspect it.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Insert or replace an entry by CID.
    pub fn upsert(&mut self, entry: Entry) {
        self.pins.insert(entry.job.cid.clone(), entry);
    }

    /// Remove an entry by CID, returning it if present.
    pub fn remove(&mut self, cid: &str) -> Option<Entry> {
        self.pins.remove(cid)
    }

    /// Look up an entry by CID.
    pub fn get(&self, cid: &str) -> Option<&Entry> {
        self.pins.get(cid)
    }

    /// Mutable lookup by CID (for the audit loop to update replica health in place).
    pub fn get_mut(&mut self, cid: &str) -> Option<&mut Entry> {
        self.pins.get_mut(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(cid: &str) -> Entry {
        Entry {
            job: PinJob {
                cid: cid.into(),
                bytes_len: 1024,
                replication: 3,
                rent_per_gb_hour: "1000000000000000".into(),
                expiry_height: 8640,
                label: Some("dataset".into()),
            },
            replicas: vec![
                Replica { holder: "host-a".into(), channel_id: "chan-a".into(), last_proof_ok: true },
                Replica { holder: "host-b".into(), channel_id: String::new(), last_proof_ok: false },
            ],
        }
    }

    #[test]
    fn roundtrips_through_disk() {
        let tmp = std::env::temp_dir().join(format!("ce-pin-test-{}", std::process::id()));
        let path = tmp.join("pins.json");
        let mut set = PinSet::default();
        set.upsert(sample_entry("cid-1"));
        set.save(&path).unwrap();

        let loaded = PinSet::load(&path).unwrap();
        assert_eq!(loaded.get("cid-1"), set.get("cid-1"));
        assert_eq!(loaded.get("cid-1").unwrap().job.rent_per_gb_hour, "1000000000000000");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_file_is_empty_set() {
        let path = std::env::temp_dir().join("ce-pin-does-not-exist-xyz/pins.json");
        let set = PinSet::load(&path).unwrap();
        assert!(set.pins.is_empty());
    }

    #[test]
    fn healthy_replicas_counts_only_verified() {
        let e = sample_entry("c");
        assert_eq!(e.healthy_replicas(), 1); // host-a ok, host-b not
    }

    #[test]
    fn upsert_replaces_and_remove_works() {
        let mut set = PinSet::default();
        set.upsert(sample_entry("c"));
        let mut updated = sample_entry("c");
        updated.job.replication = 9;
        set.upsert(updated);
        assert_eq!(set.get("c").unwrap().job.replication, 9);
        assert!(set.remove("c").is_some());
        assert!(set.get("c").is_none());
    }
}
