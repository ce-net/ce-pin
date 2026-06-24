//! Node-free tests for the host's new robustness machinery: admission control, capacity accounting,
//! garbage-collection / eviction ordering, held-set atomic persistence + corruption recovery, the
//! repair planner, and metrics. These exercise the pure logic the host loop relies on, so a
//! regression in any of them fails `cargo test` without needing a live mesh.

use ce_pin::config::HostConfig;
use ce_pin::held::{HeldEntry, HeldSet};
use ce_pin::metrics::HostMetrics;
use ce_pin::pinset::Replica;
use ce_pin::repair::repair_plan;

fn entry(bytes: u64, rent: &str, expiry: u64, last_access: u64) -> HeldEntry {
    HeldEntry {
        bytes,
        rent_per_gb_hour: rent.into(),
        expiry_height: expiry,
        pinned_at: 0,
        last_access,
        publisher: String::new(),
    }
}

#[test]
fn admission_rejects_oversize_low_rent_and_over_capacity() {
    let cfg = HostConfig {
        max_object_bytes: 1_000,
        capacity_bytes: 2_000,
        min_rent_per_gb_hour: 100,
        ..Default::default()
    };
    // Too big.
    assert!(cfg.admit(1_001, "100", 0).is_err());
    // Rent below the floor.
    assert!(cfg.admit(500, "99", 0).is_err());
    // Over the capacity budget (already holding 1800, +500 -> 2300 > 2000).
    assert!(cfg.admit(500, "100", 1_800).is_err());
    // A fitting, paying, sized object is admitted.
    assert!(cfg.admit(500, "100", 1_000).is_ok());
}

#[test]
fn gc_evicts_expired_first_then_low_rent_then_lru() {
    let mut held = HeldSet::default();
    held.insert("expired".into(), entry(100, "9999", 5, 999)); // expired -> evicted first
    held.insert("cheap".into(), entry(100, "1", 0, 500)); // lowest live rent
    held.insert("lru".into(), entry(100, "5", 0, 1)); // least-recently used
    held.insert("keep".into(), entry(100, "5", 0, 999)); // recent + decent rent -> survives
    // Budget 150 at height 60 -> must free 250: expired + cheap + lru (300 freed), keep survives.
    let victims = held.evict_to_fit(150, 60);
    assert_eq!(victims[0], "expired");
    assert!(!victims.contains(&"keep".to_string()));
    assert_eq!(victims.len(), 3);
}

#[test]
fn expired_lease_is_collected() {
    let mut held = HeldSet::default();
    held.insert("a".into(), entry(1, "0", 10, 0));
    held.insert("b".into(), entry(1, "0", 0, 0)); // open-ended
    let exp = held.expired(50);
    assert_eq!(exp, vec!["a".to_string()]);
}

#[test]
fn held_set_persists_atomically_and_survives_reload() {
    let dir = std::env::temp_dir().join(format!("ce-pin-hostlogic-{}", std::process::id()));
    let path = dir.join("held.json");
    let mut held = HeldSet::default();
    held.insert("cid-1".into(), entry(4096, "1000", 8640, 7));
    held.save(&path).unwrap();
    let back = HeldSet::load(&path).unwrap();
    assert_eq!(back.total_bytes(), 4096);
    assert!(back.contains("cid-1"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_held_set_is_preserved_not_silently_dropped() {
    let dir = std::env::temp_dir().join(format!("ce-pin-hostlogic-corrupt-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("held.json");
    std::fs::write(&path, b"{ not valid json at all").unwrap();
    // A corrupt file MUST surface an error (so the operator notices) rather than returning an empty
    // set that silently erases every paid commitment.
    assert!(HeldSet::load(&path).is_err());
    assert!(path.with_extension("corrupt").exists(), "corrupt file is moved aside for forensics");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repair_plan_restores_the_factor_excluding_current_holders() {
    let replicas = vec![
        Replica { holder: "a".into(), channel_id: String::new(), last_proof_ok: false },
        Replica { holder: "b".into(), channel_id: String::new(), last_proof_ok: false },
    ];
    // Only "a" passed -> need 2 more to reach factor 3; both current holders excluded.
    let plan = repair_plan(&replicas, &["a".to_string()], 3);
    assert_eq!(plan.to_place, 2);
    assert!(plan.exclude.contains(&"a".to_string()) && plan.exclude.contains(&"b".to_string()));
}

#[test]
fn metrics_track_admission_and_audit_outcomes() {
    let m = HostMetrics::new();
    m.offer_accepted();
    m.offer_declined();
    m.audit_passed();
    m.audit_failed();
    m.add_evictions(2);
    let s = m.snapshot();
    assert_eq!(s.offers_accepted, 1);
    assert_eq!(s.offers_declined, 1);
    assert_eq!(s.audits_passed, 1);
    assert_eq!(s.audits_failed, 1);
    assert_eq!(s.gc_evictions, 2);
}
