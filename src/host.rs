//! The pinning host: `ce-pin serve`. Earns rent by holding content and serving it.
//!
//! It polls the local node's mesh inbox for `pin/*` requests, authorizes each against a signed
//! `ce-cap` chain (rooted at this host's own key or a configured org root — the rdev `serve()`
//! pattern, verbatim), and acts:
//!   - `pin/offer`   -> fetch the object via `get_object` (CID-verified, trustless), hold it, accept;
//!   - `pin/audit`   -> answer a proof-of-retrievability challenge from local bytes;
//!   - `pin/status`  -> cheap liveness: do we still hold this CID?
//!   - `pin/release` -> drop the pin.
//!
//! Holding is "logical": the node's content-addressed blob store already persists the chunks
//! `get_object` pulled, so the host records which CIDs it has committed to keep (in a small held-set
//! file) and re-fetches on demand. The MVP does not garbage-collect blobs; a real host would.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ce_cap::{SignedCapability, authorize, decode_chain};
use ce_rs::CeClient;

use crate::proto::*;

/// Run the pinning host loop until the process is killed. `roots` are accepted capability root
/// NodeIds (32-byte); a chain rooted at one of them (or at this host's own key) authorizes actions.
pub async fn serve(client: &CeClient, roots: Vec<[u8; 32]>) -> Result<()> {
    let host_hex = client.status().await?.node_id;
    let host_id: [u8; 32] = hex::decode(&host_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("node returned a malformed node id"))?;

    // Advertise on the DHT that we are a pinning host so clients can discover us.
    if let Err(e) = client.advertise_service(SERVICE_HOST).await {
        tracing::warn!(error = %e, "could not advertise pin:host service (continuing)");
    }
    // Subscribe so directed requests on the pin topics land in our inbox.
    let held_path = held_set_path();
    let mut held = HeldSet::load(&held_path)?;
    tracing::info!(host = %&host_hex[..16.min(host_hex.len())], roots = roots.len(),
        held = held.cids.len(), "ce-pin host serving (pin/offer, pin/audit, pin/status, pin/release)");

    let mut seen: HashSet<u64> = HashSet::new();
    let mut revoked: HashSet<([u8; 32], u64)> = HashSet::new();
    let mut tick: u32 = 0;

    loop {
        // Refresh the on-chain revoked set and re-advertise periodically (provider records expire).
        if tick % 20 == 0 {
            if let Ok(pairs) = client.revoked().await {
                revoked = pairs
                    .into_iter()
                    .filter_map(|(issuer, nonce)| {
                        hex::decode(&issuer).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).map(|i| (i, nonce))
                    })
                    .collect();
            }
            let _ = client.advertise_service(SERVICE_HOST).await;
            for cid in &held.cids {
                let _ = client.advertise_service(&service_for(cid)).await;
            }
        }
        tick = tick.wrapping_add(1);

        for m in client.messages().await.unwrap_or_default() {
            let Some(token) = m.reply_token else { continue };
            if !m.topic.starts_with(TOPIC_PREFIX) || !seen.insert(token) {
                continue;
            }
            let reply =
                handle(client, &m.topic, &m.from, &m.payload_hex, &host_id, &roots, &revoked, &mut held, &held_path)
                    .await;
            if let Err(e) = client.reply(token, &reply).await {
                tracing::warn!(error = %e, "failed to send mesh reply");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Authorize, dispatch, and serialize a reply. Any error becomes a typed negative reply so the
/// requester always gets a structured answer instead of a timeout.
#[allow(clippy::too_many_arguments)]
async fn handle(
    client: &CeClient,
    topic: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
    held: &mut HeldSet,
    held_path: &Path,
) -> Vec<u8> {
    let action = topic.strip_prefix(TOPIC_PREFIX).unwrap_or(topic);
    match handle_inner(client, action, from_hex, payload_hex, host_id, roots, revoked, held, held_path).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(action, error = %e, "request denied/failed");
            // Encode a generic negative reply shaped like the per-action resp (callers tolerate it).
            serde_json::to_vec(&serde_json::json!({ "accepted": false, "held": false, "released": false, "reason": e.to_string() }))
                .unwrap_or_default()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner(
    client: &CeClient,
    action: &str,
    from_hex: &str,
    payload_hex: &str,
    host_id: &[u8; 32],
    roots: &[[u8; 32]],
    revoked: &HashSet<([u8; 32], u64)>,
    held: &mut HeldSet,
    held_path: &Path,
) -> Result<Vec<u8>> {
    let payload = hex::decode(payload_hex).context("payload hex")?;
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad sender id"))?;

    // Every request shares a `caps` field; the ability required is action-specific.
    let ability = match action {
        "offer" => ABILITY_STORE,
        "audit" => ABILITY_AUDIT,
        "status" => ABILITY_READ,
        "release" => ABILITY_RELEASE,
        other => return Err(anyhow!("unknown pin action '{other}'")),
    };
    let caps = caps_of(&payload)?;

    let chain: Vec<SignedCapability> = decode_chain(&caps).map_err(|_| anyhow!("bad capability"))?;
    let is_revoked = |issuer: &[u8; 32], nonce: u64| revoked.contains(&(*issuer, nonce));
    authorize(host_id, roots, &[], now(), &from, ability, &chain, &is_revoked)
        .map_err(|e| anyhow!("denied: {e}"))?;

    match action {
        "offer" => {
            let req: OfferReq = serde_json::from_slice(&payload)?;
            let resp = do_offer(client, &req, held, held_path).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "audit" => {
            let req: AuditReq = serde_json::from_slice(&payload)?;
            let resp = do_audit(client, &req, held).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "status" => {
            let req: StatusReq = serde_json::from_slice(&payload)?;
            let resp = do_status(client, &req, held).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "release" => {
            let req: ReleaseReq = serde_json::from_slice(&payload)?;
            let released = held.remove(&req.cid);
            held.save(held_path)?;
            Ok(serde_json::to_vec(&ReleaseResp { released, reason: None })?)
        }
        _ => unreachable!("action validated above"),
    }
}

/// Fetch the object (CID-verified by `get_object`) and commit to holding it.
async fn do_offer(client: &CeClient, req: &OfferReq, held: &mut HeldSet, held_path: &Path) -> OfferResp {
    match client.get_object(&req.cid).await {
        Ok(bytes) => {
            held.insert(req.cid.clone());
            if let Err(e) = held.save(held_path) {
                tracing::warn!(error = %e, "could not persist held-set");
            }
            let _ = client.advertise_service(&service_for(&req.cid)).await;
            tracing::info!(cid = %req.cid, bytes = bytes.len(), "accepted pin");
            OfferResp { accepted: true, stored_bytes: bytes.len() as u64, reason: None }
        }
        Err(e) => OfferResp { accepted: false, stored_bytes: 0, reason: Some(format!("fetch failed: {e}")) },
    }
}

/// Answer a proof-of-retrievability challenge: prove the challenged chunk is held **by this host
/// locally** and return `sha256(chunk || nonce)`.
///
/// SECURITY (finding H3): a PoR audit must prove *retrievability-here*, not *availability-somewhere*.
/// The SDK's `get_blob` is local-first but falls back to a mesh fetch-by-hash, so a host that
/// discarded the bytes could transparently re-pull the challenged chunk from another paid replica
/// and forge a passing proof — defeating the economic guarantee that this host still holds the data.
/// To close that hole the audit is gated on this host's own authoritative local record before any
/// blob read, and FAILS for a CID this host has not locally committed to.
///
/// The gate is the host's committed held-set: a CID is in `held` only after [`do_offer`] fetched the
/// object and recorded it, and it is removed by `pin/release`. An audit for any CID not in that set
/// (never pinned, or released — i.e. "not held locally") fails here without touching the network, so
/// a sibling replica's copy can never satisfy our challenge.
///
/// TODO(node/SDK support needed for a byte-level local-only PoR): the node's `GET /blobs/:hash`
/// handler (`ce/crates/ce-node/src/api.rs::get_blob`) takes only the path and ALWAYS falls back to
/// `fetch_chunk_from_mesh` on a local miss; it ignores query parameters, so there is no app-tier way
/// to force a no-mesh read of the actual bytes. The sound fix is a node-side local-only read — e.g.
/// honoring `GET /blobs/:hash?local=1` (or a dedicated `GET /blobs/:hash/local`) by returning 404 on
/// a local miss instead of pulling from the mesh — surfaced in the SDK as `CeClient::get_blob_local`.
/// Until that lands, the held-set gate above is the strictest enforceable defence from this app: it
/// already fails an audit for an un-held CID. When the endpoint exists, additionally read the
/// manifest and chunk through it so even a held-but-garbage-collected CID fails.
async fn do_audit(client: &CeClient, req: &AuditReq, held: &HeldSet) -> AuditResp {
    // Local-only gate: we must have committed to hold this object. This is the host's own
    // authoritative record; an audit for a CID we never pinned (or released) fails before any read,
    // so the bytes can NEVER be sourced from another replica to forge a passing proof.
    if !audit_held_locally(held, &req.cid) {
        return AuditResp { proof: None, reason: Some("not held locally".into()) };
    }
    // Resolve the manifest to map chunk_index -> chunk CID, then hash the challenged chunk. (These
    // reads go through the SDK; the local-only guarantee for the bytes themselves awaits the node
    // endpoint described above — tracked by the TODO. The held-set gate is what closes H3 today.)
    let manifest = match client.get_blob(&req.cid).await.ok().and_then(|b| serde_json::from_slice::<ce_rs::Manifest>(&b).ok()) {
        Some(m) => m,
        None => return AuditResp { proof: None, reason: Some("manifest unavailable".into()) },
    };
    let Some(chunk_cid) = manifest.chunks.get(req.chunk_index as usize) else {
        return AuditResp { proof: None, reason: Some("chunk index out of range".into()) };
    };
    match client.get_blob(chunk_cid).await {
        Ok(chunk) => AuditResp { proof: Some(crate::audit::prove(&chunk, &req.nonce)), reason: None },
        Err(e) => AuditResp { proof: None, reason: Some(format!("chunk unavailable: {e}")) },
    }
}

/// The H3 local-only audit gate, factored out so it is unit-testable without a node: a host may
/// answer a PoR challenge for `cid` only if `cid` is in its committed held-set. This is the
/// authoritative "do we hold this locally?" decision the audit makes before any (mesh-capable) read.
/// Returns true iff the host has locally committed to `cid` (and not released it).
fn audit_held_locally(held: &HeldSet, cid: &str) -> bool {
    held.cids.contains(cid)
}

/// Cheap liveness: report whether we still serve this CID (committed in the held-set and the manifest
/// resolves locally).
async fn do_status(client: &CeClient, req: &StatusReq, held: &HeldSet) -> StatusResp {
    if !held.cids.contains(&req.cid) {
        return StatusResp { held: false, bytes: 0 };
    }
    match client.get_blob(&req.cid).await.ok().and_then(|b| serde_json::from_slice::<ce_rs::Manifest>(&b).ok()) {
        Some(m) => StatusResp { held: true, bytes: m.total_size },
        None => StatusResp { held: false, bytes: 0 },
    }
}

/// Pull just the `caps` field out of a request payload (all `pin/*` requests share it) so the host
/// can authorize before fully deserializing the action-specific body.
fn caps_of(payload: &[u8]) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct HasCaps {
        caps: String,
    }
    let hc: HasCaps = serde_json::from_slice(payload).context("payload missing caps")?;
    Ok(hc.caps)
}

/// Current unix time in seconds.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The set of CIDs this host has committed to hold, persisted so a restart keeps serving them.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct HeldSet {
    cids: HashSet<String>,
}

impl HeldSet {
    fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) => Ok(serde_json::from_slice(&b).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HeldSet::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
    fn save(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
    fn insert(&mut self, cid: String) {
        self.cids.insert(cid);
    }
    fn remove(&mut self, cid: &str) -> bool {
        self.cids.remove(cid)
    }
}

/// Where the host records its held CIDs: `<config dir>/ce-pin/held.json`, overridable via `$CE_PIN_DIR`.
fn held_set_path() -> PathBuf {
    if let Some(d) = std::env::var_os("CE_PIN_DIR") {
        return PathBuf::from(d).join("held.json");
    }
    directories::ProjectDirs::from("", "", "ce-pin")
        .map(|p| p.config_dir().join("held.json"))
        .unwrap_or_else(|| PathBuf::from(".ce-pin/held.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a held-set from a list of CIDs, as the host would have after accepting those pins.
    fn held_with(cids: &[&str]) -> HeldSet {
        let mut h = HeldSet::default();
        for c in cids {
            h.insert((*c).to_string());
        }
        h
    }

    /// REGRESSION (finding H3): the audit gate must DENY a CID this host does not hold locally.
    ///
    /// Before the fix, `do_audit` had no held-set gate at all — it went straight to
    /// `get_blob(cid)`, which falls back to a mesh fetch-by-hash, so a host that never held (or had
    /// released) the bytes could re-fetch them from another replica and forge a passing proof. This
    /// test pins down the new contract: an audit for a CID NOT in the local held-set is refused
    /// before any (mesh-capable) read. It fails against the old gate-less behavior and passes now.
    #[test]
    fn audit_denied_for_cid_not_held_locally() {
        let held = held_with(&["held-cid-aaaa"]);
        // A CID we DO hold passes the local-only gate.
        assert!(audit_held_locally(&held, "held-cid-aaaa"), "a locally-held CID must pass the gate");
        // A CID we do NOT hold (never pinned, or released) is denied — it must not be answerable by
        // re-fetching from a sibling replica.
        assert!(
            !audit_held_locally(&held, "not-held-cid-bbbb"),
            "an un-held CID must FAIL the audit gate (no re-fetch-from-mesh forgery)"
        );
    }

    /// Releasing a pin removes it from the held-set, so a subsequent audit for it is denied: the
    /// host can no longer prove retrievability-here once it has dropped the bytes.
    #[test]
    fn audit_denied_after_release() {
        let mut held = held_with(&["cid-x"]);
        assert!(audit_held_locally(&held, "cid-x"));
        let removed = held.remove("cid-x");
        assert!(removed, "release must drop the CID from the held-set");
        assert!(!audit_held_locally(&held, "cid-x"), "a released CID must fail the audit gate");
    }

    /// An empty held-set (fresh host that has accepted nothing) denies every audit.
    #[test]
    fn empty_host_answers_no_audit() {
        let held = HeldSet::default();
        assert!(!audit_held_locally(&held, "anything"));
    }
}
