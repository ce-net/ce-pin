//! Integration tests that exercise ce-pin's public library surface without a live CE node:
//! the proof-of-retrievability round trip, placement ranking, pin-set persistence, and the exact
//! capability authorization ce-pin's host performs (a `pin:store` chain authorizes a pin; a
//! `pin:read` chain does not — attenuation is enforced).

use ce_iam_core::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_identity::Identity;
use ce_pin::audit;
use ce_pin::pinset::{Entry, PinJob, PinSet, Replica};
use ce_pin::placement::{Candidate, select};
use ce_pin::proto::{ABILITY_READ, ABILITY_STORE, service_for};

/// A deterministic identity from a tmp dir seed, so chains are reproducible per test.
fn identity(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-pin-it-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    Identity::load_or_generate(&dir).expect("identity")
}

fn never_revoked(_issuer: &[u8; 32], _nonce: u64) -> bool {
    false
}

/// A host self-issues a `pin:store` cap to a publisher; the host authorizes the publisher's pin.
#[test]
fn host_authorizes_self_issued_pin_store() {
    let host = identity("host-a");
    let publisher = identity("pub-a");

    let cap = SignedCapability::issue(
        &host,
        publisher.node_id(),
        vec![ABILITY_STORE.to_string()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let chain = vec![cap];
    let token = encode_chain(&chain);

    // Host decodes the presented chain and authorizes the `store` action — exactly what host.rs does.
    let decoded: Vec<SignedCapability> = decode_chain(&token).expect("decode");
    let res = authorize(
        &host.node_id(),
        &[],
        &[],
        0,
        &publisher.node_id(),
        ABILITY_STORE,
        &decoded,
        &never_revoked,
    );
    assert!(res.is_ok(), "self-issued pin:store cap must authorize a pin: {res:?}");
}

/// A `pin:read` cap must NOT authorize a `pin:store` action — abilities are not interchangeable.
#[test]
fn read_cap_does_not_authorize_store() {
    let host = identity("host-b");
    let publisher = identity("pub-b");

    let cap = SignedCapability::issue(
        &host,
        publisher.node_id(),
        vec![ABILITY_READ.to_string()],
        Resource::Any,
        Caveats::default(),
        2,
        None,
    );
    let chain = vec![cap];

    let res = authorize(
        &host.node_id(),
        &[],
        &[],
        0,
        &publisher.node_id(),
        ABILITY_STORE,
        &chain,
        &never_revoked,
    );
    assert!(res.is_err(), "a pin:read cap must not grant pin:store");
}

/// A chain rooted at a stranger (neither the host nor a configured root) is rejected.
#[test]
fn unrooted_chain_is_denied() {
    let host = identity("host-c");
    let stranger = identity("stranger-c");
    let publisher = identity("pub-c");

    // Stranger issues a cap it has no authority to grant on the host.
    let cap = SignedCapability::issue(
        &stranger,
        publisher.node_id(),
        vec![ABILITY_STORE.to_string()],
        Resource::Any,
        Caveats::default(),
        3,
        None,
    );
    let res = authorize(
        &host.node_id(),
        &[], // no accepted roots
        &[],
        0,
        &publisher.node_id(),
        ABILITY_STORE,
        &[cap],
        &never_revoked,
    );
    assert!(res.is_err(), "a chain rooted at a stranger must be denied");
}

/// Proof-of-retrievability: a host holding the bytes proves it; a host without them cannot.
#[test]
fn por_proof_round_trip() {
    let chunk = b"a chunk of pinned content".to_vec();
    let nonce = audit::nonce_from_seed(b"beacon|cid|0");
    let proof = audit::prove(&chunk, &nonce);
    assert!(audit::verify(&chunk, &nonce, &proof));
    // A host that lost the bytes (different content) fails the same challenge.
    assert!(!audit::verify(b"wrong bytes", &nonce, &proof));
}

/// Beacon-seeded challenge index is in-range and stable for fixed inputs.
#[test]
fn challenge_index_in_range() {
    let idx = audit::challenge_index("00ffbeac0n", &service_for("xyz"), 16);
    assert!(idx < 16);
    assert_eq!(idx, audit::challenge_index("00ffbeac0n", &service_for("xyz"), 16));
}

/// Placement prefers proven, live hosts and excludes the publisher.
#[test]
fn placement_selects_best_hosts() {
    let cands = vec![
        Candidate { node_id: "self".into(), delivered_work: 99, last_seen_secs: 1, mem_mb: 1, fault_domain: String::new() },
        Candidate { node_id: "proven".into(), delivered_work: 10, last_seen_secs: 5, mem_mb: 1, fault_domain: String::new() },
        Candidate { node_id: "newcomer".into(), delivered_work: 0, last_seen_secs: 5, mem_mb: 1, fault_domain: String::new() },
    ];
    let picked = select(&cands, 2, &["self".to_string()]);
    assert_eq!(picked, ["proven", "newcomer"]);
}

/// The pin-set survives a save/load round trip with replica health intact.
#[test]
fn pinset_persists() {
    let dir = std::env::temp_dir().join(format!("ce-pin-it-set-{}", std::process::id()));
    let path = dir.join("pins.json");
    let mut set = PinSet::default();
    set.upsert(Entry {
        job: PinJob {
            cid: "deadbeef".into(),
            bytes_len: 42,
            replication: 2,
            rent_per_gb_hour: "1000000000000000".into(),
            expiry_height: 100,
            label: None,
        },
        replicas: vec![Replica { holder: "h1".into(), channel_id: String::new(), last_proof_ok: true }],
    });
    set.save(&path).unwrap();
    let back = PinSet::load(&path).unwrap();
    assert_eq!(back.get("deadbeef").unwrap().healthy_replicas(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
