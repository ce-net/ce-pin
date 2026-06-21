//! Client-side operations: publishing content, discovering replicas, fetching by CID, checking
//! retrievability across the mesh, and the replication helper that asks N peers to pin.
//!
//! These wrap `ce-rs` calls and the `pin/*` protocol; the pure ranking/audit logic lives in
//! [`placement`](crate::placement) and [`audit`](crate::audit) so it can be tested without a node.

use anyhow::{Context, Result, anyhow};
use ce_rs::CeClient;

use crate::audit;
use crate::pinset::Replica;
use crate::placement::{Candidate, select};
use crate::proto::*;

/// Default per-request mesh timeout (ms). Offers may trigger a full object fetch on the host.
const OFFER_TIMEOUT_MS: u64 = 120_000;
const PROBE_TIMEOUT_MS: u64 = 15_000;

/// Publish a file's bytes to the content-addressed data layer and return its object CID. The bytes
/// are chunked client-side (`put_object`) and stored as blobs; the CID is the manifest hash, which
/// makes every later fetch trustless. Returns `(cid, bytes_len)`.
pub async fn add_bytes(client: &CeClient, bytes: &[u8]) -> Result<(String, u64)> {
    let cid = client.put_object(bytes).await.context("uploading object to the data layer")?;
    Ok((cid, bytes.len() as u64))
}

/// Fetch an object by CID and return its bytes. `get_object` resolves the manifest, pulls each
/// chunk (falling back to the mesh DHT when a chunk is not local), and verifies every chunk against
/// its CID before reassembling — so a corrupted or substituted byte is rejected, not returned.
pub async fn get(client: &CeClient, cid: &str) -> Result<Vec<u8>> {
    client.get_object(cid).await.with_context(|| format!("fetching object {cid}"))
}

/// Advertise on the DHT that this node holds/serves a CID (`pin/announce` semantics via
/// `advertise_service("pin:<cid>")`). Re-call periodically — provider records expire.
pub async fn announce(client: &CeClient, cid: &str) -> Result<()> {
    client.advertise_service(&service_for(cid)).await.context("advertising availability")
}

/// Discover the NodeIds currently advertising that they hold `cid` (via the DHT).
pub async fn find_replicas(client: &CeClient, cid: &str) -> Result<Vec<String>> {
    client.find_service(&service_for(cid)).await.context("finding replica holders")
}

/// Build ranked pinning-host candidates from the DHT host list + the capacity atlas + on-chain
/// history. Hosts that advertise `pin:host` and appear in the atlas are scored by proven delivered
/// work and liveness. Returns the candidates (unranked here; rank with [`placement::rank`]).
pub async fn candidate_hosts(client: &CeClient) -> Result<Vec<Candidate>> {
    let advertised = client.find_service(SERVICE_HOST).await.unwrap_or_default();
    let atlas = client.atlas().await.unwrap_or_default();
    let self_id = client.status().await.ok().map(|s| s.node_id);

    let mut out = Vec::new();
    for entry in &atlas {
        // Only consider hosts that have opted in by advertising the pin:host service.
        if !advertised.iter().any(|h| h == &entry.node_id) {
            continue;
        }
        if self_id.as_deref() == Some(entry.node_id.as_str()) {
            continue; // don't replicate to ourselves
        }
        let delivered_work = client
            .history(&entry.node_id)
            .await
            .map(|h| h.delivered_work())
            .unwrap_or(0);
        out.push(Candidate {
            node_id: entry.node_id.clone(),
            delivered_work,
            last_seen_secs: entry.last_seen_secs,
            mem_mb: entry.mem_mb,
        });
    }
    Ok(out)
}

/// Ask a single host to pin `cid`, presenting `caps`. Returns the host's structured reply.
pub async fn offer(
    client: &CeClient,
    host: &str,
    caps: &str,
    cid: &str,
    bytes_len: u64,
    rent_per_gb_hour: &str,
    expiry_height: u64,
) -> Result<OfferResp> {
    let req = OfferReq {
        caps: caps.to_string(),
        cid: cid.to_string(),
        bytes_len,
        rent_per_gb_hour: rent_per_gb_hour.to_string(),
        expiry_height,
    };
    let payload = serde_json::to_vec(&req)?;
    let reply = client
        .request(host, "pin/offer", &payload, OFFER_TIMEOUT_MS)
        .await
        .with_context(|| format!("offer to {}", &host[..16.min(host.len())]))?;
    let resp: OfferResp = serde_json::from_slice(&reply).context("decoding offer reply")?;
    Ok(resp)
}

/// The replication helper: ask up to `replication` ranked peers to pin `cid`, excluding any in
/// `exclude` (already-holding hosts during re-replication). Returns the [`Replica`] records for the
/// hosts that accepted. Capability-gated: each peer authorizes `caps` (a `pin:store` chain) before
/// fetching and holding.
#[allow(clippy::too_many_arguments)]
pub async fn replicate(
    client: &CeClient,
    cid: &str,
    bytes_len: u64,
    rent_per_gb_hour: &str,
    expiry_height: u64,
    replication: usize,
    caps: &str,
    candidates: &[Candidate],
    exclude: &[String],
) -> Result<Vec<Replica>> {
    let targets = select(candidates, replication, exclude);
    if targets.is_empty() {
        return Err(anyhow!("no eligible pinning hosts found (none advertised pin:host)"));
    }
    let mut accepted = Vec::new();
    for host in targets {
        match offer(client, &host, caps, cid, bytes_len, rent_per_gb_hour, expiry_height).await {
            Ok(r) if r.accepted => {
                tracing::info!(host = %&host[..16.min(host.len())], "host accepted pin");
                accepted.push(Replica { holder: host, channel_id: String::new(), last_proof_ok: true });
            }
            Ok(r) => tracing::warn!(host = %&host[..16.min(host.len())], reason = ?r.reason, "host declined pin"),
            Err(e) => tracing::warn!(host = %&host[..16.min(host.len())], error = %e, "offer failed"),
        }
    }
    Ok(accepted)
}

/// Audit one replica with a beacon-seeded proof-of-retrievability challenge. Returns `true` if the
/// host returned a proof matching the chunk the auditor independently fetched-and-verified.
pub async fn audit_replica(client: &CeClient, host: &str, caps: &str, cid: &str) -> Result<bool> {
    // The object's manifest tells us the chunk count; the beacon makes the challenged index
    // unpredictable to the host.
    let manifest_bytes = client.get_blob(cid).await.context("manifest for audit")?;
    let manifest: ce_rs::Manifest =
        serde_json::from_slice(&manifest_bytes).context("object manifest")?;
    if manifest.chunks.is_empty() {
        return Ok(true); // empty object: trivially retrievable
    }
    let beacon = client.beacon().await.context("beacon for audit seed")?;
    let index = audit::challenge_index(&beacon.hash, cid, manifest.chunks.len());
    let nonce = audit::nonce_from_seed(format!("{}:{}:{}", beacon.hash, cid, index).as_bytes());

    // Fetch-and-verify the challenged chunk ourselves so we know the expected proof.
    let chunk_cid = &manifest.chunks[index as usize];
    let expected_chunk = client.get_blob(chunk_cid).await.context("challenged chunk")?;
    if ce_rs::cid(&expected_chunk) != *chunk_cid {
        return Err(anyhow!("local chunk failed CID verification — cannot audit"));
    }

    let req = AuditReq { caps: caps.to_string(), cid: cid.to_string(), nonce: nonce.clone(), chunk_index: index };
    let reply = client
        .request(host, "pin/audit", &serde_json::to_vec(&req)?, PROBE_TIMEOUT_MS)
        .await
        .with_context(|| format!("audit to {}", &host[..16.min(host.len())]))?;
    let resp: AuditResp = serde_json::from_slice(&reply).context("decoding audit reply")?;
    match resp.proof {
        Some(proof) => Ok(audit::verify(&expected_chunk, &nonce, &proof)),
        None => Ok(false),
    }
}

/// Cheap retrievability probe against one host (`pin/status`): does it still hold the CID?
pub async fn probe_status(client: &CeClient, host: &str, caps: &str, cid: &str) -> Result<StatusResp> {
    let req = StatusReq { caps: caps.to_string(), cid: cid.to_string() };
    let reply = client
        .request(host, "pin/status", &serde_json::to_vec(&req)?, PROBE_TIMEOUT_MS)
        .await
        .with_context(|| format!("status to {}", &host[..16.min(host.len())]))?;
    serde_json::from_slice(&reply).context("decoding status reply")
}
