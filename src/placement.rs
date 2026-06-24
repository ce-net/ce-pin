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
    /// Fault domain this host belongs to (region/ASN/zone), derived from its atlas tags. Replicas
    /// are spread across distinct fault domains so a single datacenter/ASN failure cannot take out
    /// every copy. Empty string = unknown domain (treated as its own bucket per node).
    #[allow(clippy::struct_field_names)]
    pub fault_domain: String,
}

/// Rank candidates best-first for pinning. Ordering, in priority:
///   1. more proven delivered work (descending) — trust the hosts that have delivered;
///   2. seen more recently (ascending `last_seen_secs`) — prefer live hosts;
///   3. more free memory (descending) — a tie-break toward roomier hosts;
///   4. node_id (ascending) — a final deterministic tie-break so the order is stable.
///
/// Returns a new sorted `Vec`; the input is not mutated.
///
/// ```
/// use ce_pin::placement::{Candidate, rank};
/// let cands = vec![
///     Candidate { node_id: "newcomer".into(), delivered_work: 0,  last_seen_secs: 1,  mem_mb: 8000, fault_domain: String::new() },
///     Candidate { node_id: "proven".into(),   delivered_work: 50, last_seen_secs: 30, mem_mb: 512,  fault_domain: String::new() },
/// ];
/// // The host with proven delivered work ranks first, even though the newcomer is fresher/roomier.
/// assert_eq!(rank(&cands)[0].node_id, "proven");
/// ```
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
///
/// **Fault-domain diversity:** replicas are spread across distinct [`Candidate::fault_domain`]s so a
/// single datacenter/ASN failure cannot take out every copy. A first pass picks the best host from
/// each not-yet-used domain (round-robin, best-first); if `n` is still unmet (fewer domains than
/// `n`), a second pass fills the remainder with the next-best remaining hosts regardless of domain.
/// Hosts with an empty (unknown) fault domain are each treated as their own domain (keyed by node id)
/// so unknowns never collapse into one bucket. With all domains distinct this degrades to plain
/// best-first selection.
pub fn select(candidates: &[Candidate], n: usize, exclude: &[String]) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }
    let ranked: Vec<Candidate> = rank(candidates)
        .into_iter()
        .filter(|c| !exclude.iter().any(|e| e == &c.node_id))
        .collect();

    let domain_of = |c: &Candidate| -> String {
        if c.fault_domain.trim().is_empty() {
            // Unknown domain: unique per node so unknowns are not lumped together.
            format!("node:{}", c.node_id)
        } else {
            c.fault_domain.clone()
        }
    };

    let mut picked: Vec<String> = Vec::new();
    let mut used_domains: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Pass 1: best host from each distinct fault domain (best-first overall).
    for c in &ranked {
        if picked.len() >= n {
            break;
        }
        let d = domain_of(c);
        if used_domains.insert(d) {
            picked.push(c.node_id.clone());
        }
    }
    // Pass 2: if domains were fewer than n, top up with the next-best remaining hosts.
    if picked.len() < n {
        for c in &ranked {
            if picked.len() >= n {
                break;
            }
            if !picked.contains(&c.node_id) {
                picked.push(c.node_id.clone());
            }
        }
    }
    picked
}

/// Derive a host's fault domain from its atlas capability tags. We look for a `region:<x>` or
/// `zone:<x>` or `asn:<x>` tag (in that precedence) and return the value; absent any, the empty
/// string (unknown). This keeps placement decoupled from how operators label hosts — they advertise
/// a `region:eu-central` tag and replicas spread across regions for free.
pub fn fault_domain_from_tags(tags: &[String]) -> String {
    for prefix in ["region:", "zone:", "asn:"] {
        if let Some(t) = tags.iter().find(|t| t.starts_with(prefix)) {
            return t[prefix.len()..].to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, work: u64, seen: u64, mem: u32) -> Candidate {
        Candidate { node_id: id.into(), delivered_work: work, last_seen_secs: seen, mem_mb: mem, fault_domain: String::new() }
    }

    fn cand_in(id: &str, work: u64, domain: &str) -> Candidate {
        Candidate { node_id: id.into(), delivered_work: work, last_seen_secs: 0, mem_mb: 1, fault_domain: domain.into() }
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

    #[test]
    fn select_spreads_across_fault_domains() {
        // Two strong hosts in domain "eu", one weaker in "us". With diversity, picking 2 must NOT
        // take both eu hosts; it takes the best eu and then the us host (spread), not eu+eu.
        let cs = vec![
            cand_in("eu-strong", 100, "eu"),
            cand_in("eu-second", 90, "eu"),
            cand_in("us-weak", 10, "us"),
        ];
        let picked = select(&cs, 2, &[]);
        assert_eq!(picked[0], "eu-strong", "best host overall is picked first");
        assert_eq!(picked[1], "us-weak", "second pick spreads to a different fault domain");
    }

    #[test]
    fn select_tops_up_when_fewer_domains_than_n() {
        // Only one domain but we need 3 replicas: after one-per-domain, pass 2 fills the rest.
        let cs = vec![
            cand_in("a", 30, "eu"),
            cand_in("b", 20, "eu"),
            cand_in("c", 10, "eu"),
        ];
        let picked = select(&cs, 3, &[]);
        assert_eq!(picked, ["a", "b", "c"], "single-domain placement still fills the factor best-first");
    }

    #[test]
    fn unknown_domains_are_distinct_buckets() {
        // Empty fault domains must each be their own bucket (not collapsed), so diversity selection
        // degrades to best-first rather than picking only one unknown-domain host.
        let cs = vec![cand("a", 3, 1, 1), cand("b", 2, 1, 1), cand("c", 1, 1, 1)];
        assert_eq!(select(&cs, 3, &[]), ["a", "b", "c"]);
    }

    #[test]
    fn fault_domain_extracted_from_tags() {
        assert_eq!(fault_domain_from_tags(&["gpu".into(), "region:eu-central".into()]), "eu-central");
        assert_eq!(fault_domain_from_tags(&["zone:rack-7".into()]), "rack-7");
        assert_eq!(fault_domain_from_tags(&["docker".into()]), "");
        // region takes precedence over zone.
        assert_eq!(fault_domain_from_tags(&["zone:z1".into(), "region:r1".into()]), "r1");
    }
}
