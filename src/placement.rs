//! Replica placement: choose which hosts to ask to pin an object.
//!
//! Mesh-first and reputation-aware, exactly as the portfolio spec prescribes: candidate hosts come
//! from the DHT (`find_service("pin:host")`) and the capacity atlas; we rank them by proven
//! delivered work (`history(...).delivered_work()`) and liveness (`last_seen_secs`), preferring
//! hosts that have actually hosted-and-been-paid before and were seen recently. The ranking itself
//! is pure so it is unit-testable without a live mesh.

/// A candidate pinning host with the few signals we rank on. Built from `AtlasEntry` + `NodeHistory`
/// by the client; kept as a small owned struct so the ranking logic is network-free and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// 64-hex NodeId.
    pub node_id: String,
    /// Proven delivered work (settled jobs + heartbeats hosted). Higher = more trusted.
    pub delivered_work: u64,
    /// Seconds since this host was last seen advertising capacity. Lower = fresher / more live.
    pub last_seen_secs: u64,
    /// Free memory advertised (MiB) — a coarse capacity hint to avoid overloaded hosts.
    pub mem_mb: u32,
}

/// Rank candidates best-first for pinning. Ordering, in priority:
///   1. more proven delivered work (descending) — trust the hosts that have delivered;
///   2. seen more recently (ascending `last_seen_secs`) — prefer live hosts;
///   3. more free memory (descending) — a tie-break toward roomier hosts;
///   4. node_id (ascending) — a final deterministic tie-break so the order is stable.
///
/// Returns a new sorted `Vec`; the input is not mutated.
pub fn rank(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut v = candidates.to_vec();
    v.sort_by(|a, b| {
        b.delivered_work
            .cmp(&a.delivered_work)
            .then(a.last_seen_secs.cmp(&b.last_seen_secs))
            .then(b.mem_mb.cmp(&a.mem_mb))
            .then(a.node_id.cmp(&b.node_id))
    });
    v
}

/// Pick up to `n` distinct hosts for replication, best-first, excluding any in `exclude`
/// (e.g. the publisher itself, or hosts that already hold the object during re-replication).
pub fn select(candidates: &[Candidate], n: usize, exclude: &[String]) -> Vec<String> {
    rank(candidates)
        .into_iter()
        .map(|c| c.node_id)
        .filter(|id| !exclude.iter().any(|e| e == id))
        .take(n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, work: u64, seen: u64, mem: u32) -> Candidate {
        Candidate { node_id: id.into(), delivered_work: work, last_seen_secs: seen, mem_mb: mem }
    }

    #[test]
    fn ranks_proven_hosts_first() {
        let cs = vec![cand("a", 0, 10, 1000), cand("b", 5, 100, 500), cand("c", 5, 10, 500)];
        let ranked = rank(&cs);
        // b and c both have work 5, but c was seen more recently -> c before b; a (work 0) last.
        assert_eq!(ranked.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["c", "b", "a"]);
    }

    #[test]
    fn mem_breaks_ties_after_work_and_liveness() {
        let cs = vec![cand("x", 3, 50, 256), cand("y", 3, 50, 4096)];
        let ranked = rank(&cs);
        assert_eq!(ranked[0].node_id, "y"); // same work + liveness -> roomier first
    }

    #[test]
    fn select_excludes_and_caps() {
        let cs = vec![cand("a", 9, 1, 1), cand("b", 8, 1, 1), cand("c", 7, 1, 1)];
        let picked = select(&cs, 2, &["a".to_string()]);
        assert_eq!(picked, ["b", "c"]); // a excluded, capped at 2
    }

    #[test]
    fn select_handles_fewer_candidates_than_requested() {
        let cs = vec![cand("a", 1, 1, 1)];
        assert_eq!(select(&cs, 5, &[]), ["a"]);
    }
}
