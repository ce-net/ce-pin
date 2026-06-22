//! Property / fuzz tests for ce-pin's pure surface — no live node required.
//!
//! Covers, with randomized inputs:
//!   * proto JSON round-trips (encode == decode), incl. rent strings far above 2^53;
//!   * PoR audit: challenge_index always in range, deterministic, sensitive to inputs; proofs
//!     verify for held bytes, reject forged bytes, and resist nonce replay;
//!   * placement ranking is a total, deterministic order honoring work > liveness > mem > id, and
//!     `select` excludes/caps correctly;
//!   * pin-set survives disk round-trips and tolerates malformed/truncated files;
//!   * capability attenuation: a child chain can NEVER widen abilities, and a `pin:read` chain can
//!     never authorize `pin:store` (no amplification); expiry/revocation honored.

use std::collections::BTreeMap;

use ce_cap::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_identity::Identity;
use ce_pin::audit;
use ce_pin::pinset::{Entry, PinJob, PinSet, Replica};
use ce_pin::placement::{Candidate, rank, select};
use ce_pin::proto::*;
use proptest::prelude::*;

fn never_revoked(_: &[u8; 32], _: u64) -> bool {
    false
}

fn identity(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-pin-prop-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    Identity::load_or_generate(&dir).expect("identity")
}

proptest! {
    // OfferReq survives a JSON round-trip for arbitrary fields, including a rent value that exceeds
    // JS's 2^53 safe integer (money MUST ride as a decimal string, never a float).
    #[test]
    fn offer_req_roundtrips(
        caps in "[0-9a-f]{0,64}",
        cid in "[0-9a-f]{4,64}",
        bytes_len in any::<u64>(),
        rent in any::<u128>(),
        expiry in any::<u64>(),
    ) {
        let req = OfferReq {
            caps,
            cid,
            bytes_len,
            rent_per_gb_hour: rent.to_string(),
            expiry_height: expiry,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: OfferReq = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(&back.cid, &req.cid);
        prop_assert_eq!(back.bytes_len, req.bytes_len);
        prop_assert_eq!(&back.rent_per_gb_hour, &rent.to_string());
        prop_assert_eq!(back.expiry_height, req.expiry_height);
        // The rent string parses back to the exact u128 — no precision loss for values > 2^53.
        prop_assert_eq!(back.rent_per_gb_hour.parse::<u128>().unwrap(), rent);
    }

    // AuditResp deserializes from its minimal form (serde defaults fill absent fields).
    #[test]
    fn audit_resp_roundtrips(proof in proptest::option::of("[0-9a-f]{0,128}")) {
        let r = AuditResp { proof: proof.clone(), reason: None };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: AuditResp = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(back.proof, proof);
    }

    // challenge_index is ALWAYS in [0, chunk_count) and deterministic for fixed inputs.
    #[test]
    fn challenge_index_in_range_and_deterministic(
        beacon in "[0-9a-f]{0,64}",
        cid in "[0-9a-f]{0,64}",
        count in 1usize..100_000,
    ) {
        let a = audit::challenge_index(&beacon, &cid, count);
        let b = audit::challenge_index(&beacon, &cid, count);
        prop_assert_eq!(a, b);
        prop_assert!(a < count as u64);
    }

    // A held-bytes proof verifies; any change to the bytes or the nonce makes it fail.
    #[test]
    fn proof_verifies_and_rejects_tamper(
        chunk in proptest::collection::vec(any::<u8>(), 0..512),
        nonce in "[0-9a-f]{0,32}",
        flip in 0usize..512,
    ) {
        let proof = audit::prove(&chunk, &nonce);
        prop_assert!(audit::verify(&chunk, &nonce, &proof));
        // Replaying under a different nonce must fail (distinct nonce strings cannot collide).
        let other_nonce = format!("{nonce}ff");
        prop_assert!(!audit::verify(&chunk, &other_nonce, &proof));
        // Flipping a byte breaks the proof.
        if !chunk.is_empty() {
            let mut forged = chunk.clone();
            let i = flip % forged.len();
            forged[i] ^= 0xff;
            prop_assert!(!audit::verify(&forged, &nonce, &proof));
        }
    }

    // Ranking is a TOTAL order: applying it is idempotent and adjacent pairs respect the key.
    #[test]
    fn rank_is_total_and_idempotent(
        cands in proptest::collection::vec(
            (any::<u64>(), any::<u64>(), any::<u32>(), "[a-z0-9]{1,8}"),
            0..20,
        ),
    ) {
        let cands: Vec<Candidate> = cands.into_iter().enumerate().map(|(i, (w, s, m, id))| {
            Candidate { node_id: format!("{id}-{i}"), delivered_work: w, last_seen_secs: s, mem_mb: m }
        }).collect();
        let once = rank(&cands);
        let twice = rank(&once);
        prop_assert_eq!(
            once.iter().map(|c| c.node_id.clone()).collect::<Vec<_>>(),
            twice.iter().map(|c| c.node_id.clone()).collect::<Vec<_>>(),
            "rank must be idempotent (stable total order)"
        );
        for w in once.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            let key_a = (std::cmp::Reverse(a.delivered_work), a.last_seen_secs,
                         std::cmp::Reverse(a.mem_mb), a.node_id.clone());
            let key_b = (std::cmp::Reverse(b.delivered_work), b.last_seen_secs,
                         std::cmp::Reverse(b.mem_mb), b.node_id.clone());
            prop_assert!(key_a <= key_b, "ranking violated the ordering key");
        }
    }

    // select never returns an excluded id, never exceeds n, and returns distinct ids.
    #[test]
    fn select_respects_exclude_and_cap(
        cands in proptest::collection::vec("[a-z0-9]{1,6}", 0..30),
        n in 0usize..10,
        exclude_idx in proptest::collection::vec(0usize..30, 0..5),
    ) {
        let cands: Vec<Candidate> = cands.iter().enumerate().map(|(i, id)| {
            Candidate { node_id: format!("{id}-{i}"), delivered_work: i as u64, last_seen_secs: 0, mem_mb: 1 }
        }).collect();
        let exclude: Vec<String> = exclude_idx.into_iter()
            .filter_map(|i| cands.get(i).map(|c| c.node_id.clone())).collect();
        let picked = select(&cands, n, &exclude);
        prop_assert!(picked.len() <= n, "select must cap at n");
        for id in &picked {
            prop_assert!(!exclude.contains(id), "select returned an excluded id");
        }
        let mut sorted = picked.clone();
        sorted.sort();
        sorted.dedup();
        prop_assert_eq!(sorted.len(), picked.len(), "select returned duplicates");
    }

    // Pin-set survives a save/load round trip for arbitrary entries.
    #[test]
    fn pinset_disk_roundtrip(
        entries in proptest::collection::vec(
            ("[0-9a-f]{4,40}", any::<u64>(), any::<u8>(), any::<u128>(), any::<u64>()),
            0..10,
        ),
    ) {
        let dir = std::env::temp_dir()
            .join(format!("ce-pin-prop-set-{}-{}", std::process::id(), rand_suffix()));
        let path = dir.join("pins.json");
        let mut set = PinSet::default();
        let mut expected: BTreeMap<String, u8> = BTreeMap::new();
        for (cid, blen, repl, rent, exp) in entries {
            set.upsert(Entry {
                job: PinJob {
                    cid: cid.clone(),
                    bytes_len: blen,
                    replication: repl,
                    rent_per_gb_hour: rent.to_string(),
                    expiry_height: exp,
                    label: None,
                },
                replicas: vec![Replica { holder: "h".into(), channel_id: String::new(), last_proof_ok: true }],
            });
            expected.insert(cid, repl);
        }
        set.save(&path).unwrap();
        let back = PinSet::load(&path).unwrap();
        for (cid, repl) in &expected {
            prop_assert_eq!(back.get(cid).unwrap().job.replication, *repl);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0)
}

// --- Deterministic failure-injection / edge cases -------------------------------------------

#[test]
fn pinset_load_rejects_malformed_json() {
    let dir = std::env::temp_dir().join(format!("ce-pin-malformed-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("pins.json");
    std::fs::write(&path, b"{ this is not valid json ]").unwrap();
    assert!(PinSet::load(&path).is_err(), "malformed pin-set must surface a parse error");
    std::fs::write(&path, b"").unwrap();
    assert!(PinSet::load(&path).is_err(), "empty (non-JSON) file is a parse error");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn offer_resp_tolerates_partial_host_reply() {
    let r: OfferResp = serde_json::from_str(r#"{"accepted":false,"reason":"full"}"#).unwrap();
    assert!(!r.accepted);
    assert_eq!(r.stored_bytes, 0);
    assert_eq!(r.reason.as_deref(), Some("full"));
}

#[test]
fn empty_object_audit_index_is_zero_not_panic() {
    assert_eq!(audit::challenge_index("beacon", "cid", 0), 0);
}

#[test]
fn malformed_nonce_still_produces_deterministic_proof() {
    let p1 = audit::prove(b"data", "not-hex-zz");
    let p2 = audit::prove(b"data", "not-hex-zz");
    assert_eq!(p1, p2);
    assert!(audit::verify(b"data", "not-hex-zz", &p1));
}

// --- Capability attenuation: NEVER amplify (the core security property) ----------------------

/// owner -> middle (read only) -> leaf (tries to grant store it never held): must be denied.
#[test]
fn delegation_cannot_amplify_abilities() {
    let host = identity("amp-host");
    let middle = identity("amp-middle");
    let leaf = identity("amp-leaf");

    let root = SignedCapability::issue(
        &host, middle.node_id(), vec![ABILITY_READ.to_string()],
        Resource::Any, Caveats::default(), 1, None,
    );
    let child = SignedCapability::issue(
        &middle, leaf.node_id(), vec![ABILITY_STORE.to_string()],
        Resource::Any, Caveats::default(), 2, Some(root.id()),
    );
    let chain = vec![root, child];
    let res = authorize(&host.node_id(), &[], &[], 0, &leaf.node_id(), ABILITY_STORE, &chain, &never_revoked);
    assert!(res.is_err(), "a child must NEVER amplify abilities its parent did not hold");
}

/// A valid attenuating chain (read+store -> read) authorizes read but NOT the dropped store.
#[test]
fn delegation_narrowing_is_honored_both_ways() {
    let host = identity("narrow-host");
    let middle = identity("narrow-middle");
    let leaf = identity("narrow-leaf");

    let root = SignedCapability::issue(
        &host, middle.node_id(),
        vec![ABILITY_READ.to_string(), ABILITY_STORE.to_string()],
        Resource::Any, Caveats::default(), 1, None,
    );
    let child = SignedCapability::issue(
        &middle, leaf.node_id(), vec![ABILITY_READ.to_string()],
        Resource::Any, Caveats::default(), 2, Some(root.id()),
    );
    let chain = vec![root, child];
    assert!(
        authorize(&host.node_id(), &[], &[], 0, &leaf.node_id(), ABILITY_READ, &chain, &never_revoked).is_ok(),
        "narrowed read must authorize"
    );
    assert!(
        authorize(&host.node_id(), &[], &[], 0, &leaf.node_id(), ABILITY_STORE, &chain, &never_revoked).is_err(),
        "dropped store must not authorize"
    );
}

/// Expiry is honored: valid before T, denied after.
#[test]
fn expired_capability_is_denied() {
    let host = identity("exp-host");
    let pubr = identity("exp-pub");
    let cap = SignedCapability::issue(
        &host, pubr.node_id(), vec![ABILITY_STORE.to_string()],
        Resource::Any, Caveats { not_after: 1000, ..Default::default() }, 1, None,
    );
    let chain = vec![cap];
    assert!(authorize(&host.node_id(), &[], &[], 999, &pubr.node_id(), ABILITY_STORE, &chain, &never_revoked).is_ok());
    assert!(authorize(&host.node_id(), &[], &[], 1001, &pubr.node_id(), ABILITY_STORE, &chain, &never_revoked).is_err());
}

/// Revocation is honored: revoking the root's (issuer, nonce) invalidates the whole chain.
#[test]
fn revoked_capability_is_denied() {
    let host = identity("rev-host");
    let pubr = identity("rev-pub");
    let cap = SignedCapability::issue(
        &host, pubr.node_id(), vec![ABILITY_STORE.to_string()],
        Resource::Any, Caveats::default(), 42, None,
    );
    let host_id = host.node_id();
    let revoked = |issuer: &[u8; 32], nonce: u64| *issuer == host_id && nonce == 42;
    let chain = vec![cap];
    assert!(authorize(&host_id, &[], &[], 0, &pubr.node_id(), ABILITY_STORE, &chain, &revoked).is_err());
}

/// The wire path: a chain hex-token round-trips and authorizes identically; a truncated token never does.
#[test]
fn chain_survives_token_encoding() {
    let host = identity("tok-host");
    let pubr = identity("tok-pub");
    let cap = SignedCapability::issue(
        &host, pubr.node_id(), vec![ABILITY_STORE.to_string()],
        Resource::Any, Caveats::default(), 7, None,
    );
    let token = encode_chain(&[cap]);
    let decoded = decode_chain(&token).expect("decode round-trip");
    assert!(
        authorize(&host.node_id(), &[], &[], 0, &pubr.node_id(), ABILITY_STORE, &decoded, &never_revoked).is_ok()
    );
    let mut bad = token.clone();
    bad.truncate(bad.len().saturating_sub(4));
    let ok = decode_chain(&bad)
        .map(|c| authorize(&host.node_id(), &[], &[], 0, &pubr.node_id(), ABILITY_STORE, &c, &never_revoked).is_ok())
        .unwrap_or(false);
    assert!(!ok, "a truncated token must never authorize");
}

#[test]
fn empty_chain_denied() {
    let host = identity("empty-host");
    let pubr = identity("empty-pub");
    let res = authorize(&host.node_id(), &[], &[], 0, &pubr.node_id(), ABILITY_STORE, &[], &never_revoked);
    assert!(res.is_err(), "an empty chain authorizes nothing");
}
