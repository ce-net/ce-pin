//! ce-pin wire protocol: the typed messages exchanged over the CE mesh on the `pin/*` topics.
//!
//! Every request carries `caps` — a hex-encoded `ce-cap` capability chain — which the host
//! authorizes (rooted at the host's own key or a configured org root) before honoring the action.
//! Abilities are opaque app-chosen strings: `pin:store` (accept a pin), `pin:read` (serve private
//! content), `pin:audit` (answer a proof-of-retrievability challenge), `pin:release` (drop a pin).
//!
//! Payloads are JSON, hex-encoded by the SDK's `request`/`reply` transport. Content-addressing is
//! the integrity proof: the object CID *is* the manifest hash, and `get_object` re-verifies every
//! chunk against its CID, so a host can never serve bytes the publisher did not pin.

use serde::{Deserialize, Serialize};

/// Topic prefix for all ce-pin mesh messages.
pub const TOPIC_PREFIX: &str = "pin/";

/// Ability: a host accepts a pin only from a holder of a chain granting this.
pub const ABILITY_STORE: &str = "pin:store";
/// Ability: a host serves *private* (cap-gated) content only to a holder of this.
pub const ABILITY_READ: &str = "pin:read";
/// Ability: answer a proof-of-retrievability audit challenge.
pub const ABILITY_AUDIT: &str = "pin:audit";
/// Ability: drop a previously-accepted pin.
pub const ABILITY_RELEASE: &str = "pin:release";
/// Ability: extend the rent lease on a held pin (renew). Requires `pin:store` semantics — a renewer
/// is re-committing the host to keep the bytes, so the host gates it on the same `pin:store` ability.
pub const ABILITY_RENEW: &str = "pin:store";

/// The DHT service string a pinning host advertises for a given object, so fetchers can discover
/// replica holders without a central tracker (`advertise_service` / `find_service`).
pub fn service_for(cid: &str) -> String {
    format!("pin:{cid}")
}

/// The DHT service string advertised by any node willing to act as a pinning host. A client ranks
/// these (atlas + history) when choosing where to place replicas.
pub const SERVICE_HOST: &str = "pin:host";

/// `pin/offer` request: ask a host to fetch-and-hold an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferReq {
    /// Hex-encoded capability chain granting `pin:store` on the host.
    pub caps: String,
    /// The object CID to pin (manifest hash from `put_object`).
    pub cid: String,
    /// Total object size in bytes (informational; the host enforces its own limits).
    pub bytes_len: u64,
    /// Rent the publisher offers, in **base units** per GB-hour (decimal string; never a float).
    /// Base units: 1 credit = 10^18 base units, wei-style. The host decides if the rate is worth it.
    pub rent_per_gb_hour: String,
    /// Block height after which the publisher no longer guarantees rent; the host may drop the pin.
    pub expiry_height: u64,
}

/// `pin/offer` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OfferResp {
    /// Whether the host accepted and now holds (or is fetching) the object.
    pub accepted: bool,
    /// If accepted, the host's view of the object size after a successful fetch.
    #[serde(default)]
    pub stored_bytes: u64,
    /// Human-readable reason when `accepted == false`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `pin/renew` request: extend an existing pin's rent lease to a later `expiry_height`. The publisher
/// sends this before the old lease lapses so the host keeps (and keeps advertising) the object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewReq {
    pub caps: String,
    pub cid: String,
    /// The new (later) block height the rent lease extends to.
    pub expiry_height: u64,
    /// Optional updated rent rate (base units / GB-hour); empty keeps the existing rate.
    #[serde(default)]
    pub rent_per_gb_hour: String,
}

/// `pin/renew` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenewResp {
    /// Whether the host renewed (it must still hold the CID).
    pub renewed: bool,
    /// The host's resulting expiry height after the renew (0 if not renewed).
    #[serde(default)]
    pub expiry_height: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `pin/audit` request: a proof-of-retrievability challenge. The host must prove it still holds the
/// object by hashing a specific chunk (selected unpredictably via the chain `beacon`) salted with a
/// nonce. A host that no longer has the bytes cannot produce the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReq {
    pub caps: String,
    pub cid: String,
    /// Caller-chosen random nonce (hex) mixed into the proof so prior answers cannot be replayed.
    pub nonce: String,
    /// The chunk index the host must prove possession of. The auditor derives this from the public
    /// `beacon` hash so neither side can bias it; see [`audit::challenge_index`](crate::audit).
    pub chunk_index: u64,
}

/// `pin/audit` reply: the proof `= sha256(chunk_bytes || nonce_bytes)`, hex-encoded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditResp {
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `pin/release` request: ask a host to drop a pin it holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseReq {
    pub caps: String,
    pub cid: String,
}

/// `pin/release` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReleaseResp {
    pub released: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `pin/status` request: a lightweight liveness probe — does the host still hold the CID? Unlike
/// `pin/audit` this returns no proof (cheap to answer); use it for fast retrievability checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReq {
    pub caps: String,
    pub cid: String,
}

/// `pin/status` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusResp {
    /// True if the host currently holds the object locally and can serve it.
    pub held: bool,
    /// Size in bytes the host holds for this CID (0 if not held).
    #[serde(default)]
    pub bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_strings_are_cid_namespaced() {
        assert_eq!(service_for("abc123"), "pin:abc123");
        assert_ne!(service_for("abc123"), SERVICE_HOST);
    }

    #[test]
    fn offer_roundtrips_json() {
        let req = OfferReq {
            caps: "deadbeef".into(),
            cid: "f00d".into(),
            bytes_len: 4096,
            rent_per_gb_hour: "1000000000000000".into(),
            expiry_height: 8640,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: OfferReq = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.cid, "f00d");
        assert_eq!(back.rent_per_gb_hour, "1000000000000000");
        assert_eq!(back.expiry_height, 8640);
    }

    #[test]
    fn resp_defaults_when_fields_absent() {
        // A minimal host that only sets `accepted` must still deserialize.
        let r: OfferResp = serde_json::from_str(r#"{"accepted":true}"#).unwrap();
        assert!(r.accepted);
        assert_eq!(r.stored_bytes, 0);
        assert!(r.reason.is_none());
    }
}
