//! Host-side configuration: admission control and capacity limits, resolved from the environment.
//!
//! A pinning host is a paid, untrusted-input-facing service: any holder of a `pin:store` capability
//! can ask it to fetch-and-hold arbitrary content. Without bounds that is a disk/bandwidth DoS and a
//! pricing fiction. [`HostConfig`] makes the host's economics and limits explicit and enforceable:
//!
//!   * `max_object_bytes`  — reject any single object larger than this (the publisher's declared
//!                           `bytes_len` is checked *before* fetching, and the actual fetched size is
//!                           re-checked after, so a lying `bytes_len` cannot smuggle a huge object in);
//!   * `capacity_bytes`    — the host's total disk budget for pinned content; an offer that would push
//!                           the held total over this is rejected unless GC can free enough room;
//!   * `min_rent_per_gb_hour` — the lowest rent (base units) the host will accept; zero-rent offers are
//!                           declined when this is set above zero (pricing becomes real);
//!   * `max_concurrent`    — the number of `pin/*` requests served in parallel (head-of-line-blocking
//!                           bound; offers can trigger a slow full-object fetch).
//!
//! Everything is overridable via `CE_PIN_*` env vars so an operator tunes a host without recompiling.
//! Defaults are deliberately generous-but-finite so a fresh `ce-pin serve` is usable yet not unbounded.

use std::time::Duration;

/// Default maximum single-object size a host accepts: 2 GiB. Generous for a CDN edge, finite.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default total capacity budget a host devotes to pinned content: 64 GiB.
pub const DEFAULT_CAPACITY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Default minimum rent (base units / GB-hour) a host requires: 0 (accept anything). Operators that
/// want real pricing set `CE_PIN_MIN_RENT` to a positive base-unit value.
pub const DEFAULT_MIN_RENT_PER_GB_HOUR: u128 = 0;
/// Default number of `pin/*` requests served concurrently.
pub const DEFAULT_MAX_CONCURRENT: usize = 8;
/// Default per-offer object-fetch timeout (seconds) — a stalled fetch must not pin a worker forever.
pub const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 180;
/// Upper bound on the de-dup `seen` reply-token window so a long-lived host cannot leak memory.
pub const DEFAULT_SEEN_WINDOW: usize = 65_536;

/// Resolved host admission/capacity configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Reject any object whose size exceeds this (bytes).
    pub max_object_bytes: u64,
    /// Total disk budget for held content (bytes). GC keeps the held total at or below this.
    pub capacity_bytes: u64,
    /// Minimum accepted rent, base units per GB-hour. Offers below this are declined.
    pub min_rent_per_gb_hour: u128,
    /// Maximum number of `pin/*` requests handled concurrently.
    pub max_concurrent: usize,
    /// Timeout for the per-offer object fetch.
    pub fetch_timeout: Duration,
    /// Size cap for the de-dup `seen` reply-token window.
    pub seen_window: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            capacity_bytes: DEFAULT_CAPACITY_BYTES,
            min_rent_per_gb_hour: DEFAULT_MIN_RENT_PER_GB_HOUR,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            fetch_timeout: Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS),
            seen_window: DEFAULT_SEEN_WINDOW,
        }
    }
}

impl HostConfig {
    /// Build a [`HostConfig`] from `CE_PIN_*` environment variables, falling back to the defaults for
    /// any unset or unparseable value. Recognised:
    ///   * `CE_PIN_MAX_OBJECT_BYTES`
    ///   * `CE_PIN_CAPACITY_BYTES`
    ///   * `CE_PIN_MIN_RENT`            (base units per GB-hour)
    ///   * `CE_PIN_MAX_CONCURRENT`
    ///   * `CE_PIN_FETCH_TIMEOUT_SECS`
    ///   * `CE_PIN_SEEN_WINDOW`
    pub fn from_env() -> Self {
        let mut c = HostConfig::default();
        if let Some(v) = env_u64("CE_PIN_MAX_OBJECT_BYTES") {
            c.max_object_bytes = v;
        }
        if let Some(v) = env_u64("CE_PIN_CAPACITY_BYTES") {
            c.capacity_bytes = v;
        }
        if let Some(v) = env_u128("CE_PIN_MIN_RENT") {
            c.min_rent_per_gb_hour = v;
        }
        if let Some(v) = env_usize("CE_PIN_MAX_CONCURRENT") {
            // A zero would deadlock the worker pool; clamp to at least 1.
            c.max_concurrent = v.max(1);
        }
        if let Some(v) = env_u64("CE_PIN_FETCH_TIMEOUT_SECS") {
            c.fetch_timeout = Duration::from_secs(v.max(1));
        }
        if let Some(v) = env_usize("CE_PIN_SEEN_WINDOW") {
            c.seen_window = v.max(1024);
        }
        c
    }

    /// Decide whether an offer for an object of `declared_bytes` at `rent_per_gb_hour` (base-unit
    /// decimal string) is admissible *before* fetching, given the bytes already held. Returns
    /// `Ok(())` if it should be fetched, or `Err(reason)` describing the rejection (surfaced to the
    /// publisher as `OfferResp { accepted: false, reason }`). `held_bytes` is the host's current
    /// total; an offer that, summed in, would exceed `capacity_bytes` is rejected here (GC of expired
    /// pins is attempted by the caller first, so this is the post-GC check).
    pub fn admit(
        &self,
        declared_bytes: u64,
        rent_per_gb_hour: &str,
        held_bytes: u64,
    ) -> Result<(), String> {
        if declared_bytes > self.max_object_bytes {
            return Err(format!(
                "object too large: {declared_bytes} bytes exceeds host max {} bytes",
                self.max_object_bytes
            ));
        }
        // Parse the offered rent as base units. A malformed rent string is treated as zero so the
        // min-rent gate still applies (a publisher cannot bypass pricing with a junk rent field).
        let rent: u128 = rent_per_gb_hour.trim().parse().unwrap_or(0);
        if rent < self.min_rent_per_gb_hour {
            return Err(format!(
                "rent too low: {rent} base/GB-hour is below host minimum {}",
                self.min_rent_per_gb_hour
            ));
        }
        // Capacity: would holding this object push us over budget? (Saturating add: a u64 overflow
        // would itself be over any sane budget.)
        let projected = held_bytes.saturating_add(declared_bytes);
        if projected > self.capacity_bytes {
            return Err(format!(
                "insufficient capacity: holding {declared_bytes} more bytes would reach {projected}, \
                 over the host budget of {}",
                self.capacity_bytes
            ));
        }
        Ok(())
    }
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}
fn env_u128(key: &str) -> Option<u128> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}
fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_admits_a_normal_object() {
        let c = HostConfig::default();
        assert!(c.admit(1_000_000, "1000000000000000", 0).is_ok());
    }

    #[test]
    fn rejects_object_over_max_size() {
        let c = HostConfig { max_object_bytes: 1024, ..Default::default() };
        let err = c.admit(2048, "1", 0).unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn rejects_rent_below_minimum() {
        let c = HostConfig { min_rent_per_gb_hour: 1_000, ..Default::default() };
        let err = c.admit(10, "999", 0).unwrap_err();
        assert!(err.contains("rent too low"), "{err}");
        // Exactly the minimum is accepted.
        assert!(c.admit(10, "1000", 0).is_ok());
    }

    #[test]
    fn malformed_rent_is_treated_as_zero() {
        let c = HostConfig { min_rent_per_gb_hour: 1, ..Default::default() };
        assert!(c.admit(10, "not-a-number", 0).is_err(), "junk rent must not bypass the gate");
    }

    #[test]
    fn rejects_offer_over_capacity_budget() {
        let c = HostConfig { capacity_bytes: 1000, ..Default::default() };
        // Already holding 600; a 500-byte object would reach 1100 > 1000.
        let err = c.admit(500, "0", 600).unwrap_err();
        assert!(err.contains("capacity"), "{err}");
        // 400 fits exactly (600 + 400 == 1000).
        assert!(c.admit(400, "0", 600).is_ok());
    }

    #[test]
    fn from_env_clamps_zero_concurrency() {
        // SAFETY: single-threaded test; set then clear immediately.
        unsafe {
            std::env::set_var("CE_PIN_MAX_CONCURRENT", "0");
        }
        let c = HostConfig::from_env();
        unsafe {
            std::env::remove_var("CE_PIN_MAX_CONCURRENT");
        }
        assert!(c.max_concurrent >= 1, "zero concurrency would deadlock; must clamp to >=1");
    }
}
