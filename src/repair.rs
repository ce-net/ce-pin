//! The auto re-replication / repair loop — `ce-pin watch`.
//!
//! A real pinning service does not just place replicas once; it continuously maintains the desired
//! replication factor as hosts drop, fail audits, or let leases lapse. This module ties the existing
//! building blocks together:
//!   * audit every known replica of every pin (beacon-seeded PoR),
//!   * count the healthy ones,
//!   * when `healthy < desired`, [`replicate`](crate::client::replicate) to fresh hosts
//!     (`exclude`-ing the still-healthy holders) to restore the factor,
//!   * pay accrued rent on each healthy replica's channel (a rising cumulative receipt),
//!   * persist the updated replica health + channel ids back to the pin-set atomically.
//!
//! [`repair_once`] is one pass (testable, returns a summary); [`watch`] loops it on an interval until
//! cancelled. The pure decision — *how many new replicas to place given the audit results* — is
//! [`repair_plan`], unit-tested without a node.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use ce_rs::CeClient;

use crate::client as pin_client;
use crate::pinset::{Entry, PinSet, Replica};

/// A pure repair decision for one pin: given the desired replication factor and which current
/// replicas passed their audit, decide how many NEW replicas to place and which holders to exclude
/// (the healthy ones we keep). Deterministic and node-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// How many additional replicas to place to reach the desired factor (0 if already healthy).
    pub to_place: usize,
    /// Holders to exclude from new placement (the still-healthy ones — do not double-place on them).
    pub exclude: Vec<String>,
}

/// Compute the repair plan for one entry from its per-replica audit results. `healthy` is the set of
/// holders whose audit passed this round; `desired` is the target replication factor.
pub fn repair_plan(replicas: &[Replica], healthy: &[String], desired: usize) -> RepairPlan {
    let healthy_count = replicas.iter().filter(|r| healthy.contains(&r.holder)).count();
    let to_place = desired.saturating_sub(healthy_count);
    // Exclude every current holder (healthy or not) so we never re-place on a host already tracked;
    // a failing host is better dropped than re-offered in the same pass.
    let exclude: Vec<String> = replicas.iter().map(|r| r.holder.clone()).collect();
    RepairPlan { to_place, exclude }
}

/// Summary of one repair pass over the whole pin-set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairReport {
    /// Pins examined.
    pub pins_checked: usize,
    /// Pins that were under-replicated and triggered placement.
    pub pins_repaired: usize,
    /// New replicas successfully placed across all pins.
    pub replicas_added: usize,
    /// Replicas that failed their audit this pass.
    pub replicas_unhealthy: usize,
}

/// Run one repair pass over the pin-set at `pinset_path`, auditing each replica and re-replicating
/// under-provisioned pins. `caps` is the capability chain presented to hosts. Persists updated health
/// + new replicas atomically. Returns a [`RepairReport`].
pub async fn repair_once(client: &CeClient, pinset_path: &Path, caps: &str) -> Result<RepairReport> {
    let mut set = PinSet::load(pinset_path)?;
    let cids: Vec<String> = set.pins.keys().cloned().collect();
    let mut report = RepairReport::default();
    let mut dirty = false;

    for cid in cids {
        let Some(entry) = set.get(&cid).cloned() else { continue };
        report.pins_checked += 1;

        // 1. Audit each current replica; collect the healthy holders.
        let mut healthy: Vec<String> = Vec::new();
        for r in &entry.replicas {
            match pin_client::audit_replica(client, &r.holder, caps, &cid).await {
                Ok(true) => healthy.push(r.holder.clone()),
                Ok(false) => report.replicas_unhealthy += 1,
                Err(e) => {
                    report.replicas_unhealthy += 1;
                    tracing::debug!(cid = %cid, host = %&r.holder[..16.min(r.holder.len())], error = %e, "audit error");
                }
            }
        }

        // 2. Write back per-replica health accurately (only the holder that passed is marked ok).
        if let Some(e) = set.get_mut(&cid) {
            for r in e.replicas.iter_mut() {
                r.last_proof_ok = healthy.contains(&r.holder);
            }
            dirty = true;
        }

        // 3. Pay accrued rent on healthy channels (best-effort; failure does not block repair).
        pay_rent_for(client, &entry).await;

        // 4. Decide whether to place more replicas.
        let plan = repair_plan(&entry.replicas, &healthy, entry.job.replication as usize);
        if plan.to_place == 0 {
            continue;
        }
        report.pins_repaired += 1;

        let candidates = pin_client::candidate_hosts(client).await.unwrap_or_default();
        if candidates.is_empty() {
            tracing::warn!(cid = %cid, "under-replicated but no candidate hosts available");
            continue;
        }
        match pin_client::replicate(
            client,
            &cid,
            entry.job.bytes_len,
            &entry.job.rent_per_gb_hour,
            entry.job.expiry_height,
            plan.to_place,
            caps,
            &candidates,
            &plan.exclude,
        )
        .await
        {
            Ok(new_replicas) => {
                report.replicas_added += new_replicas.len();
                if let Some(e) = set.get_mut(&cid) {
                    for nr in new_replicas {
                        // Avoid duplicate holder entries if a re-placement landed on a known host.
                        if !e.replicas.iter().any(|r| r.holder == nr.holder) {
                            e.replicas.push(nr);
                        }
                    }
                    dirty = true;
                }
                tracing::info!(cid = %cid, placed = report.replicas_added, "repaired under-replicated pin");
            }
            Err(e) => tracing::warn!(cid = %cid, error = %e, "re-replication failed"),
        }
    }

    if dirty {
        set.save(pinset_path)?;
    }
    Ok(report)
}

/// Pay accrued rent on each healthy replica's channel for one entry. The cumulative is computed from
/// the object size, the elapsed lease so far, and the rent rate (pure integer money). Best-effort.
async fn pay_rent_for(client: &CeClient, entry: &Entry) {
    let rent_base: u128 = entry.job.rent_per_gb_hour.trim().parse().unwrap_or(0);
    if rent_base == 0 {
        return;
    }
    // Elapsed hours since the lease started, approximated from the chain tip vs expiry window. We do
    // not have per-replica start heights persisted, so we bill the full lease window conservatively
    // (the host redeems the highest receipt, so an over-estimate is capped by the channel capacity).
    let hours = 1; // one billing increment per pass; cumulative rises each pass the host stays healthy
    for r in &entry.replicas {
        if r.channel_id.is_empty() || !r.last_proof_ok {
            continue;
        }
        let owed = pin_client::rent_owed_base(entry.job.bytes_len, hours, rent_base);
        if let Err(e) = pin_client::pay_rent(client, r, owed).await {
            tracing::debug!(host = %&r.holder[..16.min(r.holder.len())], error = %e, "rent receipt failed");
        }
    }
}

/// Loop [`repair_once`] every `interval`, until `cancel` resolves. Logs each pass's report. This is
/// the `ce-pin watch` daemon. Errors in a single pass are logged and the loop continues.
pub async fn watch<F>(client: &CeClient, pinset_path: &Path, caps: &str, interval: Duration, cancel: F) -> Result<()>
where
    F: std::future::Future<Output = ()>,
{
    tracing::info!(interval_secs = interval.as_secs(), "ce-pin watch: repair daemon started");
    tokio::pin!(cancel);
    loop {
        match repair_once(client, pinset_path, caps).await {
            Ok(report) => tracing::info!(
                checked = report.pins_checked,
                repaired = report.pins_repaired,
                added = report.replicas_added,
                unhealthy = report.replicas_unhealthy,
                "repair pass complete"
            ),
            Err(e) => tracing::warn!(error = %e, "repair pass failed"),
        }
        tokio::select! {
            _ = &mut cancel => {
                tracing::info!("ce-pin watch: shutting down");
                return Ok(());
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(holder: &str) -> Replica {
        Replica { holder: holder.into(), channel_id: String::new(), last_proof_ok: false }
    }

    #[test]
    fn no_placement_when_fully_healthy() {
        let replicas = vec![replica("a"), replica("b"), replica("c")];
        let healthy = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let plan = repair_plan(&replicas, &healthy, 3);
        assert_eq!(plan.to_place, 0, "a fully-healthy pin needs no repair");
    }

    #[test]
    fn places_the_shortfall() {
        let replicas = vec![replica("a"), replica("b"), replica("c")];
        // Only "a" passed -> 2 of 3 are unhealthy; need 2 more to reach 3.
        let healthy = vec!["a".to_string()];
        let plan = repair_plan(&replicas, &healthy, 3);
        assert_eq!(plan.to_place, 2);
        // All current holders are excluded from new placement.
        assert!(plan.exclude.contains(&"a".to_string()));
        assert!(plan.exclude.contains(&"b".to_string()));
        assert!(plan.exclude.contains(&"c".to_string()));
    }

    #[test]
    fn places_full_factor_when_all_dead() {
        let replicas = vec![replica("a")];
        let plan = repair_plan(&replicas, &[], 3);
        assert_eq!(plan.to_place, 3, "all replicas dead -> place the full desired factor");
    }

    #[test]
    fn never_over_places_when_more_healthy_than_desired() {
        let replicas = vec![replica("a"), replica("b"), replica("c"), replica("d")];
        let healthy = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let plan = repair_plan(&replicas, &healthy, 2);
        assert_eq!(plan.to_place, 0, "over-replicated pins do not place more (saturating_sub)");
    }
}
