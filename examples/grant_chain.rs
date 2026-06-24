//! Runnable example: forge and verify the `ce-cap` capability chain a ce-pin host authorizes,
//! entirely offline (no node). Demonstrates the trust model end-to-end:
//!
//!   1. a HOST self-issues a `pin:store` + `pin:audit` capability to a PUBLISHER (signed by the
//!      host's own key — the host is the root of trust for its own resources);
//!   2. the chain is encoded to the hex token the publisher would pass via `--caps`;
//!   3. the host decodes and `authorize()`s the publisher for a `pin:store` action — exactly what
//!      `ce_pin::host::serve` does on each `pin/offer`;
//!   4. attenuation is shown: the same chain does NOT authorize an ability it never granted.
//!
//! Run with: `cargo run --example grant_chain`
//!
//! This mirrors the production `ce grant <publisher> --can pin:store,pin:audit` workflow without
//! needing a running node, so you can see precisely what the host checks.

use ce_cap::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_identity::Identity;
use ce_pin::proto::{ABILITY_RELEASE, ABILITY_STORE};

fn main() -> anyhow::Result<()> {
    // Deterministic identities from temp dirs (a real host/publisher use their node key).
    let host = identity("example-host");
    let publisher = identity("example-publisher");

    println!("host      = {}", hex::encode(host.node_id()));
    println!("publisher = {}", hex::encode(publisher.node_id()));

    // 1. The host self-issues a capability to the publisher. abilities = pin:store + pin:audit.
    let cap = SignedCapability::issue(
        &host,
        publisher.node_id(),
        vec!["pin:store".to_string(), "pin:audit".to_string()],
        Resource::Any, // scope to a specific resource in production for least privilege
        Caveats::default(),
        1, // nonce — must be unique per issued cap so revocation can target it
        None,
    );

    // 2. Encode the chain to the hex token the publisher passes via --caps / $CE_PIN_CAPS.
    let token = encode_chain(&[cap]);
    println!("\ncapability token (pass to `ce-pin add --caps <hex>`):\n{token}\n");

    // 3. The host authorizes a pin:store action — the exact call `host::serve` makes per request.
    let chain: Vec<SignedCapability> = decode_chain(&token)?;
    let now = 0; // unix seconds; caveats are checked against this
    let never_revoked = |_issuer: &[u8; 32], _nonce: u64| false;

    match authorize(
        &host.node_id(),
        &[], // accepted roots beyond the host itself; none here
        &[], // host self-tags
        now,
        &publisher.node_id(),
        ABILITY_STORE,
        &chain,
        &never_revoked,
    ) {
        Ok(()) => println!("AUTHORIZED: publisher may perform `{ABILITY_STORE}` (pin accepted)."),
        Err(e) => println!("DENIED: {e}"),
    }

    // 4. Attenuation: the very same chain does NOT grant `pin:release` — it was never delegated.
    match authorize(
        &host.node_id(),
        &[],
        &[],
        now,
        &publisher.node_id(),
        ABILITY_RELEASE,
        &chain,
        &never_revoked,
    ) {
        Ok(()) => println!("UNEXPECTED: pin:release should not have been granted!"),
        Err(_) => println!("DENIED (correctly): the chain never granted `{ABILITY_RELEASE}`."),
    }

    Ok(())
}

fn identity(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-pin-example-{tag}"));
    let _ = std::fs::create_dir_all(&dir);
    Identity::load_or_generate(&dir).expect("identity")
}
