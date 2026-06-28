//! The pinning host: `ce-pin serve`. Earns rent by holding content and serving it.
//!
//! It polls the local node's mesh inbox for `pin/*` requests, authorizes each against a signed
//! `ce-cap` chain (rooted at this host's own key or a configured org root — the rdev `serve()`
//! pattern, verbatim), and acts:
//!   - `pin/offer`   -> admission-check (size/rent/capacity), fetch the object via `get_object`
//!                      (CID-verified, trustless), hold it with accounting, accept;
//!   - `pin/audit`   -> answer a proof-of-retrievability challenge from local bytes (gated on the
//!                      committed held-set so the bytes can never be re-sourced from a sibling replica);
//!   - `pin/status`  -> cheap liveness: do we still hold this CID?
//!   - `pin/renew`   -> extend the rent lease on a held CID;
//!   - `pin/release` -> drop the pin.
//!
//! The inbound serve loop is [`ce_rs::serve`] — the shared mesh-app serving loop (SSE inbox push +
//! reply-token de-duplication + reconnect/backoff) — so this app no longer hand-rolls its own poll
//! loop. The host supplies a [`Handler`] that authorizes and dispatches `pin/*` requests; periodic
//! maintenance (revocation refresh, re-advertisement, GC) runs on an independent timer task.
//!
//! Robustness properties (vs the original MVP):
//!   * **Admission control** ([`crate::config::HostConfig`]): rejects oversized objects, below-minimum
//!     rent, and offers that would exceed the host's disk budget — closing the DoS / pricing-fiction.
//!   * **Capacity accounting + GC**: the held-set tracks bytes per CID; a background loop evicts
//!     expired-then-lowest-rent-then-LRU pins to stay under budget and drops past-lease pins.
//!   * **Shared serve loop**: `ce_rs::serve` de-duplicates redelivered requests (bounded set) and
//!     reconnects to the inbox with capped backoff; the held-set is an `Arc<Mutex<..>>` so the
//!     handler is race-free against the maintenance task, and each offer's fetch has a timeout.
//!   * **Atomic, corruption-safe persistence**: the held-set is written temp-file + fsync + rename and
//!     a corrupt file is preserved (not silently dropped).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ce_iam_core::{SignedCapability, authorize, decode_chain};
use ce_rs::CeClient;
use ce_rs::serve::{Handler, Request, serve_where};
use tokio::sync::Mutex;

use crate::config::HostConfig;
use crate::held::{HeldEntry, HeldSet};
use crate::metrics::HostMetrics;
use crate::proto::*;

/// Shared host state passed to every request handler. Cheap to clone (all `Arc`).
#[derive(Clone)]
struct HostState {
    host_id: [u8; 32],
    roots: Arc<Vec<[u8; 32]>>,
    revoked: Arc<Mutex<HashSet<([u8; 32], u64)>>>,
    held: Arc<Mutex<HeldSet>>,
    held_path: Arc<PathBuf>,
    cfg: Arc<HostConfig>,
    metrics: Arc<HostMetrics>,
}

/// Run the pinning host loop until the process is killed. `roots` are accepted capability root
/// NodeIds (32-byte); a chain rooted at one of them (or at this host's own key) authorizes actions.
/// Configuration (size/rent/capacity/concurrency) is read from `CE_PIN_*` env vars; see
/// [`HostConfig::from_env`].
pub async fn serve(client: &CeClient, roots: Vec<[u8; 32]>) -> Result<()> {
    serve_with(client, roots, HostConfig::from_env()).await
}

/// As [`serve`] but with an explicit [`HostConfig`] (used by tests to inject tight limits).
pub async fn serve_with(client: &CeClient, roots: Vec<[u8; 32]>, cfg: HostConfig) -> Result<()> {
    let host_hex = client.status().await?.node_id;
    let host_id: [u8; 32] = hex::decode(&host_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("node returned a malformed node id"))?;

    if let Err(e) = client.advertise_service(SERVICE_HOST).await {
        tracing::warn!(error = %e, "could not advertise pin:host service (continuing)");
    }

    let held_path = held_set_path();
    let held = HeldSet::load(&held_path)?;
    tracing::info!(
        host = %&host_hex[..16.min(host_hex.len())],
        roots = roots.len(),
        held = held.len(),
        held_bytes = held.total_bytes(),
        capacity = cfg.capacity_bytes,
        max_object = cfg.max_object_bytes,
        min_rent = cfg.min_rent_per_gb_hour,
        concurrency = cfg.max_concurrent,
        "ce-pin host serving (offer/audit/status/renew/release)"
    );

    let state = HostState {
        host_id,
        roots: Arc::new(roots),
        revoked: Arc::new(Mutex::new(HashSet::new())),
        held: Arc::new(Mutex::new(held)),
        held_path: Arc::new(held_path),
        cfg: Arc::new(cfg),
        metrics: Arc::new(HostMetrics::new()),
    };

    // Periodic maintenance (revocation refresh + re-advertisement + GC + metrics) runs on its own
    // timer task, decoupled from inbound message flow so it keeps ticking under load or idle.
    let maint = tokio::spawn(maintenance_loop(client.clone(), state.clone()));

    // The inbound serve loop is `ce_rs::serve`: it pushes from the SSE inbox, de-duplicates
    // redelivered reply tokens, reconnects with backoff, and replies for us. We accept any `pin/*`
    // topic and dispatch through the host handler. ctrl_c shuts it down cleanly.
    let pin_handler = PinHandler { client: client.clone(), state: state.clone() };
    let result = serve_where(
        client,
        &[],
        |topic| topic.starts_with(TOPIC_PREFIX),
        &pin_handler,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await;

    maint.abort();
    result
}

/// The host's mesh-request handler: authorize the signed capability chain, dispatch the `pin/*`
/// action, and return the serialized reply. `ce_rs::serve` owns the inbox/dedup/reconnect/reply
/// loop and calls this once per request; the handler never blocks on anything unbounded (each
/// offer's fetch is timeout-bounded in [`do_offer`]).
struct PinHandler {
    client: CeClient,
    state: HostState,
}

impl Handler for PinHandler {
    async fn handle(&self, req: Request) -> Vec<u8> {
        handle(&self.client, &req.topic, &req.from, &hex::encode(&req.payload), &self.state).await
    }
}

/// Background maintenance: refresh the revoked set + re-advertise every ~10s, GC + log metrics
/// every ~30s. Runs until aborted (on shutdown). Mirrors the cadence of the old poll-tick loop
/// (20 ticks * 500ms ~= 10s; 60 ticks ~= 30s) without coupling it to inbound traffic.
async fn maintenance_loop(client: CeClient, state: HostState) {
    // Run the startup pass immediately (tick 0 in the old loop did revoked+readvertise+gc).
    refresh_revoked(&client, &state).await;
    readvertise(&client, &state).await;
    run_gc(&client, &state).await;

    let mut every_10s = tokio::time::interval(Duration::from_secs(10));
    let mut every_30s = tokio::time::interval(Duration::from_secs(30));
    every_10s.tick().await; // consume the immediate first tick (startup pass already ran)
    every_30s.tick().await;
    loop {
        tokio::select! {
            _ = every_10s.tick() => {
                refresh_revoked(&client, &state).await;
                readvertise(&client, &state).await;
            }
            _ = every_30s.tick() => {
                run_gc(&client, &state).await;
                let s = state.metrics.snapshot();
                let held = state.held.lock().await;
                tracing::info!(
                    accepted = s.offers_accepted, declined = s.offers_declined, failed = s.offers_failed,
                    audits_ok = s.audits_passed, audits_fail = s.audits_failed, evictions = s.gc_evictions,
                    denied = s.auth_denied, held = held.len(), held_bytes = held.total_bytes(),
                    "ce-pin host metrics"
                );
            }
        }
    }
}

/// Refresh the on-chain revoked set so a revoked capability stops authorizing within ~10s.
async fn refresh_revoked(client: &CeClient, state: &HostState) {
    if let Ok(pairs) = client.revoked().await {
        let set: HashSet<([u8; 32], u64)> = pairs
            .into_iter()
            .filter_map(|(issuer, nonce)| {
                hex::decode(&issuer).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).map(|i| (i, nonce))
            })
            .collect();
        *state.revoked.lock().await = set;
    }
}

/// Re-advertise the host service and every held CID (provider records expire on the DHT).
async fn readvertise(client: &CeClient, state: &HostState) {
    let _ = client.advertise_service(SERVICE_HOST).await;
    let cids: Vec<String> = state.held.lock().await.entries.keys().cloned().collect();
    for cid in cids {
        let _ = client.advertise_service(&service_for(&cid)).await;
    }
}

/// Background garbage collection: drop pins whose rent lease expired, then (if still over the disk
/// budget) evict by expired > lowest-rent > LRU until the held total fits. Persists the result
/// atomically and stops advertising dropped CIDs.
async fn run_gc(client: &CeClient, state: &HostState) {
    let height = client.status().await.map(|s| s.height).unwrap_or(0);
    let mut dropped: Vec<String> = Vec::new();
    {
        let mut held = state.held.lock().await;
        // 1. Expired leases.
        for cid in held.expired(height) {
            held.remove(&cid);
            dropped.push(cid);
        }
        // 2. Capacity: evict to fit the budget.
        let victims = held.evict_to_fit(state.cfg.capacity_bytes, height);
        for cid in victims {
            held.remove(&cid);
            dropped.push(cid);
        }
        if !dropped.is_empty() {
            if let Err(e) = held.save(&state.held_path) {
                tracing::warn!(error = %e, "GC could not persist held-set");
            }
        }
    }
    if !dropped.is_empty() {
        state.metrics.add_evictions(dropped.len() as u64);
        tracing::info!(count = dropped.len(), "GC dropped pins (expired or over-budget)");
        // We intentionally do NOT re-advertise the dropped CIDs; their provider records lapse.
    }
}

/// Authorize, dispatch, and serialize a reply. Any error becomes a typed negative reply so the
/// requester always gets a structured answer instead of a timeout.
async fn handle(client: &CeClient, topic: &str, from_hex: &str, payload_hex: &str, state: &HostState) -> Vec<u8> {
    let action = topic.strip_prefix(TOPIC_PREFIX).unwrap_or(topic);
    match handle_inner(client, action, from_hex, payload_hex, state).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(action, error = %e, "request denied/failed");
            serde_json::to_vec(&serde_json::json!({
                "accepted": false, "held": false, "released": false, "renewed": false,
                "reason": e.to_string()
            }))
            .unwrap_or_default()
        }
    }
}

async fn handle_inner(
    client: &CeClient,
    action: &str,
    from_hex: &str,
    payload_hex: &str,
    state: &HostState,
) -> Result<Vec<u8>> {
    let payload = hex::decode(payload_hex).context("payload hex")?;
    let from: [u8; 32] = hex::decode(from_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad sender id"))?;

    let ability = match action {
        "offer" => ABILITY_STORE,
        "audit" => ABILITY_AUDIT,
        "status" => ABILITY_READ,
        "renew" => ABILITY_RENEW,
        "release" => ABILITY_RELEASE,
        other => return Err(anyhow!("unknown pin action '{other}'")),
    };
    let caps = caps_of(&payload)?;

    let chain: Vec<SignedCapability> = decode_chain(&caps).map_err(|_| anyhow!("bad capability"))?;
    let revoked = state.revoked.lock().await.clone();
    let is_revoked = |issuer: &[u8; 32], nonce: u64| revoked.contains(&(*issuer, nonce));
    if let Err(e) = authorize(&state.host_id, &state.roots, &[], now(), &from, ability, &chain, &is_revoked) {
        state.metrics.auth_deny();
        return Err(anyhow!("denied: {e}"));
    }

    match action {
        "offer" => {
            let req: OfferReq = serde_json::from_slice(&payload)?;
            let resp = do_offer(client, &req, from_hex, state).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "audit" => {
            let req: AuditReq = serde_json::from_slice(&payload)?;
            let resp = do_audit(client, &req, state).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "status" => {
            let req: StatusReq = serde_json::from_slice(&payload)?;
            let resp = do_status(client, &req, state).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "renew" => {
            let req: RenewReq = serde_json::from_slice(&payload)?;
            let resp = do_renew(&req, state).await;
            Ok(serde_json::to_vec(&resp)?)
        }
        "release" => {
            let req: ReleaseReq = serde_json::from_slice(&payload)?;
            let mut held = state.held.lock().await;
            // Was it held before we removed it? (remove returns freed bytes, which is 0 for a
            // 0-byte commitment, so check membership first to report `released` accurately.)
            let was_held = held.contains(&req.cid);
            held.remove(&req.cid);
            held.save(&state.held_path)?;
            drop(held);
            if was_held {
                state.metrics.release();
            }
            Ok(serde_json::to_vec(&ReleaseResp { released: was_held, reason: None })?)
        }
        _ => unreachable!("action validated above"),
    }
}

/// Admission-check, fetch the object (CID-verified by `get_object`, with a timeout), and commit to
/// holding it with full accounting.
async fn do_offer(client: &CeClient, req: &OfferReq, publisher: &str, state: &HostState) -> OfferResp {
    // Admission BEFORE any fetch: size, rent, and (post-expired-GC) capacity. Re-offering a CID we
    // already hold is always admissible (idempotent refresh) and does not double-count capacity.
    let already_held = state.held.lock().await.contains(&req.cid);
    if !already_held {
        let held_bytes = {
            // Opportunistically GC expired pins first so capacity reflects reclaimable space.
            let height = client.status().await.map(|s| s.height).unwrap_or(0);
            let mut held = state.held.lock().await;
            for cid in held.expired(height) {
                held.remove(&cid);
            }
            held.total_bytes()
        };
        if let Err(reason) = state.cfg.admit(req.bytes_len, &req.rent_per_gb_hour, held_bytes) {
            state.metrics.offer_declined();
            tracing::info!(cid = %req.cid, %reason, "declined pin (admission)");
            return OfferResp { accepted: false, stored_bytes: 0, reason: Some(reason) };
        }
    }

    // Fetch with a timeout so a stalled mesh pull cannot pin a worker for the full SDK timeout.
    let fetched = tokio::time::timeout(state.cfg.fetch_timeout, client.get_object(&req.cid)).await;
    let bytes = match fetched {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            state.metrics.offer_failed();
            return OfferResp { accepted: false, stored_bytes: 0, reason: Some(format!("fetch failed: {e}")) };
        }
        Err(_) => {
            state.metrics.offer_failed();
            return OfferResp {
                accepted: false,
                stored_bytes: 0,
                reason: Some(format!("fetch timed out after {}s", state.cfg.fetch_timeout.as_secs())),
            };
        }
    };

    // Re-check the ACTUAL fetched size against the max — a lying `bytes_len` cannot smuggle a huge
    // object past the size gate.
    let actual = bytes.len() as u64;
    if !already_held && actual > state.cfg.max_object_bytes {
        state.metrics.offer_declined();
        return OfferResp {
            accepted: false,
            stored_bytes: 0,
            reason: Some(format!(
                "fetched object is {actual} bytes, over host max {}",
                state.cfg.max_object_bytes
            )),
        };
    }

    let entry = HeldEntry {
        bytes: actual,
        rent_per_gb_hour: req.rent_per_gb_hour.clone(),
        expiry_height: req.expiry_height,
        pinned_at: now(),
        last_access: now(),
        publisher: publisher.to_string(),
    };
    {
        let mut held = state.held.lock().await;
        held.insert(req.cid.clone(), entry);
        if let Err(e) = held.save(&state.held_path) {
            tracing::warn!(error = %e, "could not persist held-set");
        }
    }
    let _ = client.advertise_service(&service_for(&req.cid)).await;
    state.metrics.offer_accepted();
    tracing::info!(cid = %req.cid, bytes = actual, "accepted pin");
    OfferResp { accepted: true, stored_bytes: actual, reason: None }
}

/// Answer a proof-of-retrievability challenge: prove the challenged chunk is held **by this host
/// locally** and return `sha256(chunk || nonce)`.
///
/// SECURITY (finding H3): a PoR audit must prove *retrievability-here*, not *availability-somewhere*.
/// The SDK's `get_blob` is local-first but falls back to a mesh fetch-by-hash, so a host that
/// discarded the bytes could transparently re-pull the challenged chunk from another paid replica
/// and forge a passing proof. The audit is therefore gated on this host's authoritative committed
/// held-set BEFORE any blob read, and FAILS for a CID this host has not locally committed to (never
/// pinned, released, or GC-evicted) — so a sibling replica's copy can never satisfy our challenge.
///
/// TODO(node/SDK support for byte-level local-only PoR): the node's `GET /blobs/:hash` always falls
/// back to `fetch_chunk_from_mesh` on a local miss and ignores query params, so there is no app-tier
/// way to force a no-mesh byte read. The sound fix is a node-side local-only read (`?local=1` -> 404
/// on a local miss) surfaced as `CeClient::get_blob_local`; until then the held-set gate is the
/// strictest enforceable defence (it already fails an audit for an un-held CID). See README "PoR".
async fn do_audit(client: &CeClient, req: &AuditReq, state: &HostState) -> AuditResp {
    if !audit_held_locally(&*state.held.lock().await, &req.cid) {
        state.metrics.audit_failed();
        return AuditResp { proof: None, reason: Some("not held locally".into()) };
    }
    let manifest = match client
        .get_blob(&req.cid)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<ce_rs::Manifest>(&b).ok())
    {
        Some(m) => m,
        None => {
            state.metrics.audit_failed();
            return AuditResp { proof: None, reason: Some("manifest unavailable".into()) };
        }
    };
    let Some(chunk_cid) = manifest.chunks.get(req.chunk_index as usize) else {
        state.metrics.audit_failed();
        return AuditResp { proof: None, reason: Some("chunk index out of range".into()) };
    };
    match client.get_blob(chunk_cid).await {
        Ok(chunk) => {
            state.metrics.audit_passed();
            state.held.lock().await.touch(&req.cid, now());
            AuditResp { proof: Some(crate::audit::prove(&chunk, &req.nonce)), reason: None }
        }
        Err(e) => {
            state.metrics.audit_failed();
            AuditResp { proof: None, reason: Some(format!("chunk unavailable: {e}")) }
        }
    }
}

/// The H3 local-only audit gate, factored out so it is unit-testable without a node: a host may
/// answer a PoR challenge for `cid` only if `cid` is in its committed held-set.
fn audit_held_locally(held: &HeldSet, cid: &str) -> bool {
    held.contains(cid)
}

/// Extend the rent lease on a held CID. Fails if the host does not hold it (a renew is not a back
/// door to pin a new object — use `pin/offer` for that).
async fn do_renew(req: &RenewReq, state: &HostState) -> RenewResp {
    let mut held = state.held.lock().await;
    let Some(entry) = held.entries.get_mut(&req.cid) else {
        return RenewResp { renewed: false, expiry_height: 0, reason: Some("not held locally".into()) };
    };
    // Only ever extend the lease, never shorten it (a publisher cannot use renew to drop the lease).
    if req.expiry_height > entry.expiry_height || entry.expiry_height == 0 {
        entry.expiry_height = req.expiry_height;
    }
    if !req.rent_per_gb_hour.trim().is_empty() {
        entry.rent_per_gb_hour = req.rent_per_gb_hour.clone();
    }
    entry.last_access = now();
    let new_expiry = entry.expiry_height;
    if let Err(e) = held.save(&state.held_path) {
        tracing::warn!(error = %e, "could not persist held-set after renew");
    }
    RenewResp { renewed: true, expiry_height: new_expiry, reason: None }
}

/// Cheap liveness: report whether we still serve this CID (committed in the held-set and the manifest
/// resolves locally).
async fn do_status(client: &CeClient, req: &StatusReq, state: &HostState) -> StatusResp {
    if !state.held.lock().await.contains(&req.cid) {
        return StatusResp { held: false, bytes: 0 };
    }
    match client.get_blob(&req.cid).await.ok().and_then(|b| serde_json::from_slice::<ce_rs::Manifest>(&b).ok()) {
        Some(m) => {
            state.held.lock().await.touch(&req.cid, now());
            StatusResp { held: true, bytes: m.total_size }
        }
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

// Reply-token de-duplication used to live here (a bounded `SeenWindow`); it now lives in
// `ce_rs::serve`, which de-duplicates redelivered requests inside the shared serve loop. The
// `seen_window` knob on `HostConfig` is retained for config compatibility.

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

    fn held_with(cids: &[&str]) -> HeldSet {
        let mut h = HeldSet::default();
        for c in cids {
            h.insert(
                (*c).to_string(),
                HeldEntry {
                    bytes: 10,
                    rent_per_gb_hour: "0".into(),
                    expiry_height: 0,
                    pinned_at: 0,
                    last_access: 0,
                    publisher: String::new(),
                },
            );
        }
        h
    }

    /// REGRESSION (finding H3): the audit gate must DENY a CID this host does not hold locally.
    #[test]
    fn audit_denied_for_cid_not_held_locally() {
        let held = held_with(&["held-cid-aaaa"]);
        assert!(audit_held_locally(&held, "held-cid-aaaa"), "a locally-held CID must pass the gate");
        assert!(
            !audit_held_locally(&held, "not-held-cid-bbbb"),
            "an un-held CID must FAIL the audit gate (no re-fetch-from-mesh forgery)"
        );
    }

    /// Releasing a pin removes it from the held-set, so a subsequent audit for it is denied.
    #[test]
    fn audit_denied_after_release() {
        let mut held = held_with(&["cid-x"]);
        assert!(audit_held_locally(&held, "cid-x"));
        assert!(held.remove("cid-x") > 0, "release must drop the CID and free its bytes");
        assert!(!audit_held_locally(&held, "cid-x"), "a released CID must fail the audit gate");
    }

    /// An empty held-set (fresh host) denies every audit.
    #[test]
    fn empty_host_answers_no_audit() {
        let held = HeldSet::default();
        assert!(!audit_held_locally(&held, "anything"));
    }
}
