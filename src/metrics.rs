//! Lightweight, lock-friendly host metrics — counters a long-running pinning host exposes so an
//! operator can see throughput, admission decisions, and audit health at a glance.
//!
//! These are plain atomics (cheap, `Sync`, no lock contention on the hot path). The host bumps them
//! from its request handlers and periodically logs a snapshot; tests assert the counters move.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for a pinning host. All monotonic since process start.
#[derive(Debug, Default)]
pub struct HostMetrics {
    /// Offers accepted (object fetched and committed).
    pub offers_accepted: AtomicU64,
    /// Offers declined (admission control: size, rent, or capacity).
    pub offers_declined: AtomicU64,
    /// Offers that failed mid-fetch (network/timeout) after admission.
    pub offers_failed: AtomicU64,
    /// `pin/audit` challenges answered with a valid proof.
    pub audits_passed: AtomicU64,
    /// `pin/audit` challenges refused (not held locally / unavailable).
    pub audits_failed: AtomicU64,
    /// Pins released by request.
    pub releases: AtomicU64,
    /// Pins garbage-collected (expired or evicted for capacity).
    pub gc_evictions: AtomicU64,
    /// Requests denied by the capability gate.
    pub auth_denied: AtomicU64,
}

impl HostMetrics {
    /// A fresh zeroed set.
    pub fn new() -> Self {
        Self::default()
    }

    fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n` to a counter (used for batch GC evictions).
    pub fn add_evictions(&self, n: u64) {
        self.gc_evictions.fetch_add(n, Ordering::Relaxed);
    }

    pub fn offer_accepted(&self) {
        Self::inc(&self.offers_accepted);
    }
    pub fn offer_declined(&self) {
        Self::inc(&self.offers_declined);
    }
    pub fn offer_failed(&self) {
        Self::inc(&self.offers_failed);
    }
    pub fn audit_passed(&self) {
        Self::inc(&self.audits_passed);
    }
    pub fn audit_failed(&self) {
        Self::inc(&self.audits_failed);
    }
    pub fn release(&self) {
        Self::inc(&self.releases);
    }
    pub fn auth_deny(&self) {
        Self::inc(&self.auth_denied);
    }

    /// A point-in-time snapshot (for logging or a status endpoint).
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            offers_accepted: self.offers_accepted.load(Ordering::Relaxed),
            offers_declined: self.offers_declined.load(Ordering::Relaxed),
            offers_failed: self.offers_failed.load(Ordering::Relaxed),
            audits_passed: self.audits_passed.load(Ordering::Relaxed),
            audits_failed: self.audits_failed.load(Ordering::Relaxed),
            releases: self.releases.load(Ordering::Relaxed),
            gc_evictions: self.gc_evictions.load(Ordering::Relaxed),
            auth_denied: self.auth_denied.load(Ordering::Relaxed),
        }
    }
}

/// An immutable copy of the counters for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub offers_accepted: u64,
    pub offers_declined: u64,
    pub offers_failed: u64,
    pub audits_passed: u64,
    pub audits_failed: u64,
    pub releases: u64,
    pub gc_evictions: u64,
    pub auth_denied: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_snapshot() {
        let m = HostMetrics::new();
        m.offer_accepted();
        m.offer_accepted();
        m.offer_declined();
        m.audit_passed();
        m.add_evictions(3);
        let s = m.snapshot();
        assert_eq!(s.offers_accepted, 2);
        assert_eq!(s.offers_declined, 1);
        assert_eq!(s.audits_passed, 1);
        assert_eq!(s.gc_evictions, 3);
        assert_eq!(s.offers_failed, 0);
    }
}
