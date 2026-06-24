//! Client-side operations: publishing content, discovering replicas, fetching by CID, checking
//! retrievability across the mesh, replicating to N peers, paying rent over payment channels,
//! renewing leases, releasing pins, and repairing the replication factor.
//!
//! These wrap `ce-rs` calls and the `pin/*` protocol; the pure ranking/audit logic lives in
//! [`placement`](crate::placement) and [`audit`](crate::audit) so it can be tested without a node.

use anyhow::{Context, Result, anyhow};
use ce_rs::{Amount, CeClient};

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

/// Advertise on the DHT that this node holds/serves a CID. Re-call periodically — records expire.
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
            fault_domain: crate::placement::fault_domain_from_tags(&entry.tags),
        });
    }
    Ok(out)
}

/// Ask a single host to pin `cid`, presenting `caps`. Returns the host's structured reply.
#[allow(clippy::too_many_arguments)]
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
        .with_context(|| format!("offer to {}", short(host)))?;
    let resp: OfferResp = serde_json::from_slice(&reply).context("decoding offer reply")?;
    Ok(resp)
}

/// Channel capacity to lock when opening a rent channel: a publisher locks roughly the total rent it
/// expects to owe over the lease, `rent_per_gb_hour * GB * lease_hours`. Computed in **integer**
/// milli-GB units (never a float — money stays exact), with a small floor so a tiny object still
/// opens a usable channel.
fn channel_capacity_for(bytes_len: u64, rent_per_gb_hour_base: u128, lease_hours: u64) -> Amount {
    let gib = 1024u128 * 1024 * 1024;
    // milli-GB held, rounded UP so the locked capacity never under-funds the rent.
    let milli_gb = ((bytes_len as u128).saturating_mul(1000) + gib - 1) / gib;
    let milli_gb = milli_gb.max(1); // at least ~1 MiB worth so the estimate is non-zero
    let est = rent_per_gb_hour_base
        .saturating_mul(milli_gb)
        .saturating_mul(lease_hours as u128)
        / 1000;
    // Floor at one credit's worth so the channel is openable even for free/zero-rent pins.
    let floor = ce_rs::CREDIT as u128;
    Amount::from_base(est.max(floor) as i128)
}

/// The replication helper: ask up to `replication` ranked peers to pin `cid`, excluding any in
/// `exclude`. For each accepting host it **opens a payment channel** (when `rent` > 0 and the lease
/// has a length) and records the real `channel_id` on the [`Replica`], so rent settlement is wired —
/// not a placeholder. Returns the `Replica` records for the hosts that accepted. Capability-gated.
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
    let rent_base: u128 = rent_per_gb_hour.trim().parse().unwrap_or(0);
    let mut accepted = Vec::new();
    for host in targets {
        match offer(client, &host, caps, cid, bytes_len, rent_per_gb_hour, expiry_height).await {
            Ok(r) if r.accepted => {
                tracing::info!(host = %short(&host), "host accepted pin");
                // Open a rent channel for paid pins. A failure here is non-fatal: the pin still
                // stands; rent simply is not pre-funded (the replica records an empty channel).
                let channel_id = if rent_base > 0 && expiry_height > 0 {
                    let cap = channel_capacity_for(bytes_len, rent_base, lease_hours(client, expiry_height).await);
                    match client.channel_open(&host, cap, expiry_height).await {
                        Ok(id) => {
                            tracing::info!(host = %short(&host), channel = %id, "opened rent channel");
                            id
                        }
                        Err(e) => {
                            tracing::warn!(host = %short(&host), error = %e, "could not open rent channel (pin stands, unpaid)");
                            String::new()
                        }
                    }
                } else {
                    String::new()
                };
                accepted.push(Replica { holder: host, channel_id, last_proof_ok: true });
            }
            Ok(r) => tracing::warn!(host = %short(&host), reason = ?r.reason, "host declined pin"),
            Err(e) => tracing::warn!(host = %short(&host), error = %e, "offer failed"),
        }
    }
    Ok(accepted)
}

/// Estimate the lease length in hours from the expiry height and the chain tip, assuming ~10s
/// blocks. Used only to size a rent channel; a conservative floor of 1 hour keeps it usable.
async fn lease_hours(client: &CeClient, expiry_height: u64) -> u64 {
    let tip = client.status().await.map(|s| s.height).unwrap_or(0);
    let blocks = expiry_height.saturating_sub(tip);
    // 10s/block -> 360 blocks/hour.
    (blocks / 360).max(1)
}

/// Pay accrued rent on a replica's channel by signing a cumulative receipt for `cumulative_base`
/// (base units, the monotone total owed so far). The host redeems the highest receipt on
/// `channel_close`. No-op (Ok) if the replica has no channel (unpaid pin). Returns the signed
/// receipt's cumulative on success so the caller can persist its high-water mark.
pub async fn pay_rent(client: &CeClient, replica: &Replica, cumulative_base: u128) -> Result<Option<Amount>> {
    if replica.channel_id.is_empty() {
        return Ok(None);
    }
    let cumulative = Amount::from_base(cumulative_base as i128);
    let receipt = client
        .sign_receipt(&replica.channel_id, &replica.holder, cumulative)
        .await
        .with_context(|| format!("signing rent receipt for {}", short(&replica.holder)))?;
    Ok(Some(receipt.cumulative))
}

/// Rent owed for holding `bytes` for `hours` at `rent_per_gb_hour_base` base units per GB-hour. Pure
/// integer math (milli-GB granularity) so money never rides a float. This is the cumulative a
/// publisher signs into a receipt.
pub fn rent_owed_base(bytes: u64, hours: u64, rent_per_gb_hour_base: u128) -> u128 {
    // milli-GB = bytes * 1000 / GiB, rounded down; rent = rate * milli_gb * hours / 1000.
    let gib = 1024u128 * 1024 * 1024;
    let milli_gb = (bytes as u128).saturating_mul(1000) / gib;
    rent_per_gb_hour_base.saturating_mul(milli_gb).saturating_mul(hours as u128) / 1000
}

/// Ask a host to renew (extend) the rent lease on a CID it holds to `new_expiry_height`.
pub async fn renew(
    client: &CeClient,
    host: &str,
    caps: &str,
    cid: &str,
    new_expiry_height: u64,
    rent_per_gb_hour: &str,
) -> Result<RenewResp> {
    let req = RenewReq {
        caps: caps.to_string(),
        cid: cid.to_string(),
        expiry_height: new_expiry_height,
        rent_per_gb_hour: rent_per_gb_hour.to_string(),
    };
    let reply = client
        .request(host, "pin/renew", &serde_json::to_vec(&req)?, PROBE_TIMEOUT_MS)
        .await
        .with_context(|| format!("renew to {}", short(host)))?;
    serde_json::from_slice(&reply).context("decoding renew reply")
}

/// Ask a host to release (drop) a pin it holds, and close its rent channel if one is open. Returns
/// the host's structured reply.
pub async fn release(client: &CeClient, replica: &Replica, caps: &str, cid: &str) -> Result<ReleaseResp> {
    let req = ReleaseReq { caps: caps.to_string(), cid: cid.to_string() };
    let reply = client
        .request(&replica.holder, "pin/release", &serde_json::to_vec(&req)?, PROBE_TIMEOUT_MS)
        .await
        .with_context(|| format!("release to {}", short(&replica.holder)))?;
    let resp: ReleaseResp = serde_json::from_slice(&reply).context("decoding release reply")?;
    Ok(resp)
}

/// Audit one replica with a beacon-seeded proof-of-retrievability challenge. Returns `true` if the
/// host returned a proof matching the chunk the auditor independently fetched-and-verified. A
/// zero-chunk (empty) object returns `false` here so it is never treated as a "passing" audit — an
/// empty manifest carries no retrievability evidence and must not auto-pass (closes the audit's
/// trivially-true hole).
pub async fn audit_replica(client: &CeClient, host: &str, caps: &str, cid: &str) -> Result<bool> {
    let manifest_bytes = client.get_blob(cid).await.context("manifest for audit")?;
    let manifest: ce_rs::Manifest =
        serde_json::from_slice(&manifest_bytes).context("object manifest")?;
    if manifest.chunks.is_empty() {
        // An empty object cannot be audited (no chunk to challenge). Treat as "not provable here".
        return Ok(false);
    }
    let beacon = client.beacon().await.context("beacon for audit seed")?;
    let index = audit::challenge_index(&beacon.hash, cid, manifest.chunks.len());
    let nonce = audit::nonce_from_seed(format!("{}:{}:{}", beacon.hash, cid, index).as_bytes());

    let chunk_cid = &manifest.chunks[index as usize];
    let expected_chunk = client.get_blob(chunk_cid).await.context("challenged chunk")?;
    if ce_rs::cid(&expected_chunk) != *chunk_cid {
        return Err(anyhow!("local chunk failed CID verification — cannot audit"));
    }

    let req = AuditReq { caps: caps.to_string(), cid: cid.to_string(), nonce: nonce.clone(), chunk_index: index };
    let reply = client
        .request(host, "pin/audit", &serde_json::to_vec(&req)?, PROBE_TIMEOUT_MS)
        .await
        .with_context(|| format!("audit to {}", short(host)))?;
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
        .with_context(|| format!("status to {}", short(host)))?;
    serde_json::from_slice(&reply).context("decoding status reply")
}

/// Shorten a 64-hex node id for log lines.
fn short(id: &str) -> &str {
    &id[..16.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rent_owed_is_integer_and_scales() {
        // 1 GiB held for 1 hour at 1000 base/GB-hour == 1000 base.
        let gib = 1024u64 * 1024 * 1024;
        assert_eq!(rent_owed_base(gib, 1, 1000), 1000);
        // 2 GiB for 3 hours == 6000.
        assert_eq!(rent_owed_base(2 * gib, 3, 1000), 6000);
        // Zero rent is always zero.
        assert_eq!(rent_owed_base(gib, 100, 0), 0);
    }

    #[test]
    fn rent_owed_handles_sub_gb_objects() {
        // A 512 MiB object for 1 hour at 1000/GB-hour: milli_gb = 512Mi*1000/1Gi = 500 -> 500 base.
        let half_gib = 512u64 * 1024 * 1024;
        assert_eq!(rent_owed_base(half_gib, 1, 1000), 500);
    }

    #[test]
    fn channel_capacity_has_a_floor() {
        // Tiny object, tiny rent -> still at least 1 credit so the channel is openable.
        let cap = channel_capacity_for(1024, 1, 1);
        assert!(cap.base() >= ce_rs::CREDIT, "channel capacity must floor at one credit");
    }

    #[test]
    fn channel_capacity_scales_with_rent_and_lease() {
        let small = channel_capacity_for(2 * 1024 * 1024 * 1024, 10, 1);
        let large = channel_capacity_for(2 * 1024 * 1024 * 1024, 10, 1000);
        assert!(large.base() >= small.base(), "longer lease must not lower the locked capacity");
    }
}
