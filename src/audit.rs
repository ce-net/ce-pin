//! Proof-of-retrievability (PoR) — the pure challenge/proof logic shared by the auditor (client)
//! and the prover (host).
//!
//! The auditor picks a chunk index from an object's manifest *unpredictably* by folding the public
//! `beacon` hash (the PoW tip hash — globally agreed, no party can bias it) together with the CID.
//! It sends the index plus a fresh random nonce. The host must return
//! `proof = sha256(chunk_bytes || nonce_bytes)`. A host that has discarded the bytes cannot produce
//! the proof; replay is prevented because the nonce changes every round.
//!
//! This module is network-free so it can be unit-tested exhaustively. The host fetches the chunk
//! bytes from its local blob store; the auditor recomputes the expected proof from the chunk it
//! holds (or re-fetches) to compare.

use sha2::{Digest, Sha256};

/// Pick the chunk index to challenge, derived from the beacon hash and the object CID so it is
/// unpredictable to the host yet reproducible by any auditor. Returns an index in `[0, chunk_count)`.
/// `chunk_count == 0` yields `0` (degenerate; callers should not audit an empty object).
pub fn challenge_index(beacon_hash: &str, cid: &str, chunk_count: usize) -> u64 {
    if chunk_count == 0 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(beacon_hash.as_bytes());
    h.update(b"|");
    h.update(cid.as_bytes());
    let digest = h.finalize();
    // Fold the first 8 bytes into a u64, then reduce modulo the chunk count.
    let mut n = [0u8; 8];
    n.copy_from_slice(&digest[..8]);
    let v = u64::from_be_bytes(n);
    v % (chunk_count as u64)
}

/// Compute the PoR proof a host returns: `sha256(chunk_bytes || nonce_bytes)`, hex-encoded.
/// `nonce_hex` is the auditor's random nonce; if it is not valid hex the raw bytes are used so a
/// malformed nonce still produces a deterministic (and therefore comparable) result.
pub fn prove(chunk_bytes: &[u8], nonce_hex: &str) -> String {
    let nonce = hex::decode(nonce_hex).unwrap_or_else(|_| nonce_hex.as_bytes().to_vec());
    let mut h = Sha256::new();
    h.update(chunk_bytes);
    h.update(&nonce);
    hex::encode(h.finalize())
}

/// Verify a host's proof against the chunk the auditor holds (or re-fetched and CID-verified).
/// Constant-relevant comparison is unnecessary here — both sides are public hashes.
pub fn verify(expected_chunk: &[u8], nonce_hex: &str, proof: &str) -> bool {
    prove(expected_chunk, nonce_hex) == proof
}

/// Generate a fresh nonce from a 32-byte seed (e.g. a beacon hash concatenated with a counter).
/// Kept seed-based rather than pulling in an `rng` crate so the unit tests stay deterministic and
/// the production path has no extra dependency; callers should seed it with unpredictable input.
pub fn nonce_from_seed(seed: &[u8]) -> String {
    hex::encode(Sha256::digest(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_in_range_and_deterministic() {
        let a = challenge_index("beacon-hash-aaaa", "cid-xyz", 7);
        let b = challenge_index("beacon-hash-aaaa", "cid-xyz", 7);
        assert_eq!(a, b, "same inputs -> same index");
        assert!(a < 7);
    }

    #[test]
    fn index_changes_with_beacon() {
        // A different beacon (next block) should usually move the index — assert it can differ over
        // a small spread of beacons rather than for one specific pair (avoids a flaky equality).
        let base = challenge_index("beacon-0", "cid", 100);
        let moved = (1..20).any(|i| challenge_index(&format!("beacon-{i}"), "cid", 100) != base);
        assert!(moved, "varying the beacon should vary the challenged index");
    }

    #[test]
    fn empty_object_index_is_zero() {
        assert_eq!(challenge_index("b", "c", 0), 0);
    }

    #[test]
    fn proof_roundtrips() {
        let chunk = b"the quick brown fox";
        let nonce = "00ff00ff";
        let proof = prove(chunk, nonce);
        assert!(verify(chunk, nonce, &proof));
    }

    #[test]
    fn proof_rejects_wrong_bytes() {
        let proof = prove(b"real chunk", "abcd");
        assert!(!verify(b"forged chunk", "abcd", &proof));
    }

    #[test]
    fn proof_rejects_replayed_nonce() {
        // A host that recorded last round's proof cannot reuse it under a new nonce.
        let chunk = b"held bytes";
        let old = prove(chunk, "1111");
        assert!(!verify(chunk, "2222", &old));
    }

    #[test]
    fn nonce_is_hex_and_stable_for_seed() {
        let n = nonce_from_seed(b"seed");
        assert_eq!(n.len(), 64);
        assert_eq!(n, nonce_from_seed(b"seed"));
    }
}
