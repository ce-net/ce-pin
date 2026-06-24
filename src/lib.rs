//! # ce-pin — content-availability / paid blob-pinning over CE
//!
//! ce-pin is an **application built on CE primitives** (the SDK tier, like `swarm` / `rdev`), not a
//! node feature. It turns CE's content-addressed blob layer into an IPFS-style pinning service
//! *with payments, capability-gated privacy, and proof-of-retrievability* — the killer property
//! being that **content-addressing IS the integrity proof**: an object's CID is the hash of its
//! manifest, and `get_object` re-verifies every chunk against its CID, so a host can never serve
//! bytes the publisher did not pin, and a cache cannot be poisoned.
//!
//! ## Shape
//! - [`pinset`]   — the client-side index (`cid -> PinJob + replicas`), persisted as JSON.
//! - [`proto`]    — the `pin/*` mesh wire protocol (offer / audit / status / release).
//! - [`placement`]— pure host-ranking (atlas capacity + on-chain history reputation).
//! - [`audit`]    — pure proof-of-retrievability challenge/proof (beacon-seeded, replay-resistant).
//! - [`client`]   — publish, fetch-by-CID, discover replicas, replicate to N peers, audit.
//! - [`host`]     — `serve()`: the capability-gated pinning host loop (earns rent).
//! - [`caps`]     — resolving the `ce-cap` chain the client presents to hosts.
//!
//! ## Trust & money (honoring CE rules)
//! Authorization is the one CE primitive: every host action verifies a signed, attenuating `ce-cap`
//! chain rooted at the host's own key or a configured org root before acting. Money is integer base
//! units (1 credit = 10^18 base units) carried as decimal strings — never floats; rent is priced in
//! base units per GB-hour and paid via CE payment channels (the SDK's `channel_open`/`sign_receipt`/
//! `channel_close`), which the CLI wires up incrementally.

pub mod audit;
pub mod caps;
pub mod client;
pub mod config;
pub mod held;
pub mod host;
pub mod metrics;
pub mod pinset;
pub mod placement;
pub mod proto;
pub mod repair;

/// Load accepted capability root keys for a pinning host: 64-hex NodeIds, one per line, `#`
/// comments allowed. Looked up at `$CE_PIN_ROOTS`, else `$CE_DATA_DIR/roots`, else
/// `~/.local/share/ce/roots` — mirroring the node's and rdev's `<data_dir>/roots`. A host opts into
/// an org/fleet by listing that org's root key here; with no file, only self-issued chains are
/// honored.
pub fn load_roots() -> Vec<[u8; 32]> {
    use std::path::PathBuf;
    let path = std::env::var_os("CE_PIN_ROOTS")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CE_DATA_DIR").map(|d| PathBuf::from(d).join("roots")))
        .or_else(|| {
            directories::ProjectDirs::from("", "", "ce")
                .map(|p| p.data_dir().join("roots"))
        })
        .unwrap_or_else(|| PathBuf::from("roots"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|h| hex::decode(h).ok().and_then(|b| b.try_into().ok()))
        .collect()
}
