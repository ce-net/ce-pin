//! Live 2-node mesh integration test for ce-pin.
//!
//! Spins up two ephemeral CE nodes (publisher + host) wired into a tiny isolated mesh, then drives
//! the REAL host loop ([`ce_pin::host::serve`]) and the REAL client helpers across the mesh:
//!
//!   1. publisher `put_object`s content -> object CID;
//!   2. host `serve()` advertises `pin:host` and answers `pin/*` requests under a real `ce-cap`
//!      chain the host self-issues to the publisher;
//!   3. publisher sends `pin/offer` -> host fetches the object BY CID from the publisher over the
//!      mesh DHT (content-addressed, trustless) and accepts;
//!   4. publisher audits the host (beacon-seeded PoR) -> proof verifies;
//!   5. publisher `pin/status` -> host reports it holds the CID;
//!   6. an UNAUTHORIZED publisher (no cap) is denied (capability gate is live, not bypassed).
//!
//! This is NOT `#[ignore]`d: it runs whenever the release `ce` binary is present (built into the
//! shared target). If the binary is absent it SKIPS with a clear message rather than failing, so
//! `cargo test` stays green on machines without a built node. No Docker/GPU needed — pinning is
//! pure mesh + blob layer.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
use ce_identity::Identity;
use ce_pin::proto::{ABILITY_AUDIT, ABILITY_READ, ABILITY_STORE};
use ce_rs::CeClient;

/// Locate the release `ce` binary in the shared target dir, env override, or PATH. `None` => skip.
fn find_ce_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CE_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    // Walk up from CARGO_MANIFEST_DIR looking for .cargo-shared/release/ce and target/release/ce.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut dir = manifest.as_path();
    loop {
        for rel in [".cargo-shared/release/ce", "target/release/ce"] {
            let cand = dir.join(rel);
            if cand.exists() {
                return Some(cand);
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    None
}

struct Node {
    child: Child,
    data_dir: PathBuf,
    api: String,
    token: String,
    p2p_port: u16,
}

impl Node {
    fn client(&self) -> CeClient {
        // Re-read the token from disk each time: the node may rewrite api.token shortly after the
        // health endpoint comes up, so the value captured at spawn can be stale.
        let token = std::fs::read_to_string(self.data_dir.join("api.token"))
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|_| self.token.clone());
        CeClient::with_token(self.api.clone(), Some(token))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn spawn_node(ce: &PathBuf, api_port: u16, p2p_port: u16, bootstrap: Option<&str>) -> Node {
    let data_dir = std::env::temp_dir().join(format!(
        "ce-pin-live-{}-{}-{}",
        std::process::id(),
        api_port,
        rand_suffix()
    ));
    std::fs::create_dir_all(&data_dir).unwrap();
    let mut cmd = Command::new(ce);
    cmd.arg("--data-dir")
        .arg(&data_dir)
        .arg("start")
        .arg("--no-mine")
        .arg("--api-port")
        .arg(api_port.to_string())
        .arg("--port")
        .arg(p2p_port.to_string())
        .arg("--ephemeral")
        .arg("--no-mdns");
    if let Some(b) = bootstrap {
        cmd.arg("--bootstrap").arg(b);
    }
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    let child = cmd.spawn().expect("spawn ce node");
    let api = format!("http://127.0.0.1:{api_port}");
    // Wait for the api.token file + health.
    let token = wait_for_token(&data_dir);
    Node { child, data_dir, api, token, p2p_port }
}

fn wait_for_token(data_dir: &std::path::Path) -> String {
    let path = data_dir.join("api.token");
    for _ in 0..200 {
        if let Ok(t) = std::fs::read_to_string(&path) {
            let t = t.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("node never wrote api.token at {}", path.display());
}

async fn wait_healthy(client: &CeClient) {
    for _ in 0..200 {
        if client.health().await.unwrap_or(false) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never became healthy");
}

/// Wait until an AUTHENTICATED write succeeds (the api.token is live). Returns a client whose token
/// was freshly read from disk. Guards against the token being rewritten just after health comes up.
async fn wait_auth_ready(node: &Node) -> CeClient {
    for _ in 0..200 {
        let c = node.client();
        if c.put_blob(b"auth-probe".to_vec()).await.is_ok() {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never accepted an authenticated write (api.token never became usable)");
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0)
}

/// Read the node's identity secret so the host's serve() loop and our self-issued capability use the
/// SAME key the node authenticates as (the cap must root at the host node's own id).
fn node_identity(data_dir: &std::path::Path) -> Identity {
    Identity::load_or_generate(&data_dir.join("identity")).expect("load node identity")
}

#[tokio::test]
async fn pin_offer_audit_status_round_trip_across_two_nodes() {
    let Some(ce) = find_ce_binary() else {
        eprintln!("SKIP: no release `ce` binary found (set CE_BIN or build it); skipping live test");
        return;
    };

    // --- Node A (publisher) ---
    let api_a = 18960;
    let p2p_a = 14960;
    let node_a = spawn_node(&ce, api_a, p2p_a, None);
    wait_healthy(&node_a.client()).await;
    let client_a = wait_auth_ready(&node_a).await;

    // Build A's dialable bootstrap multiaddr (loopback tcp) from its peer id.
    let a_status = client_a.status().await.expect("A status");
    let a_node_id = a_status.node_id.clone();
    let a_addr = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        node_a.p2p_port,
        peer_id_from_bootstrap(&node_a.api)
    );

    // --- Node B (pinning host) bootstrapped off A ---
    let api_b = 18961;
    let p2p_b = 14961;
    let node_b = spawn_node(&ce, api_b, p2p_b, Some(&a_addr));
    wait_healthy(&node_b.client()).await;
    let client_b = wait_auth_ready(&node_b).await;
    let b_node_id = client_b.status().await.expect("B status").node_id.clone();

    // Wait for the two nodes to actually peer (discovery works once connected).
    advertise_and_wait_peer(&client_b, &client_a, &b_node_id).await;

    // --- Publish content on A ---
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let cid = client_a.put_object(&payload).await.expect("put_object on A");

    // --- Host B self-issues a pin:store/read/audit cap to A (the publisher) and runs serve() ---
    let host_identity = node_identity(&node_b.data_dir);
    assert_eq!(
        hex::encode(host_identity.node_id()),
        b_node_id,
        "the identity we load for B must equal B's advertised node id"
    );
    let publisher_id = parse_id(&a_node_id);
    let cap = SignedCapability::issue(
        &host_identity,
        publisher_id,
        vec![
            ABILITY_STORE.to_string(),
            ABILITY_READ.to_string(),
            ABILITY_AUDIT.to_string(),
        ],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let caps_token = encode_chain(&[cap]);

    // Run B's REAL host loop in the background (rooted at its own key — empty extra roots).
    let serve_client = node_b.client();
    let serve_handle = tokio::spawn(async move {
        let _ = ce_pin::host::serve(&serve_client, Vec::new()).await;
    });
    // Give the loop a moment to advertise + subscribe.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // --- 1. Offer: A asks B to pin the CID (capability-gated) ---
    let resp = retry_offer(&client_a, &b_node_id, &caps_token, &cid, payload.len() as u64).await;
    assert!(resp.accepted, "host must accept an authorized pin: {:?}", resp.reason);
    assert_eq!(resp.stored_bytes, payload.len() as u64, "host stored the full object");

    // --- 2. Audit: A challenges B with a beacon-seeded PoR; the proof must verify ---
    let audited = ce_pin::client::audit_replica(&client_a, &b_node_id, &caps_token, &cid)
        .await
        .expect("audit_replica call");
    assert!(audited, "the host holding the bytes must pass the PoR audit");

    // --- 3. Status: B reports it holds the CID ---
    let st = ce_pin::client::probe_status(&client_a, &b_node_id, &caps_token, &cid)
        .await
        .expect("probe_status call");
    assert!(st.held, "host must report it holds the pinned CID");

    // --- 4. Unauthorized offer (no cap) must be denied, not silently accepted ---
    let denied =
        ce_pin::client::offer(&client_a, &b_node_id, "", &cid, payload.len() as u64, "1000", 0)
            .await
            .expect("offer call returns a structured reply even on denial");
    assert!(!denied.accepted, "an offer with NO capability must be denied");
    assert!(denied.reason.is_some(), "denial must carry a reason");

    serve_handle.abort();
    // node_a / node_b dropped here -> killed + temp dirs removed.
}

/// Read a node's libp2p peer id from its public `/bootstrap` endpoint (the multiaddr list contains
/// `/p2p/<peerid>`). Retries briefly while the node finishes starting.
fn peer_id_from_bootstrap(api: &str) -> String {
    for _ in 0..200 {
        if let Ok(resp) = ureq_get(&format!("{api}/bootstrap")) {
            if let Some(pid) = extract_peer_id(&resp) {
                return pid;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("could not determine peer id from {api}/bootstrap");
}

/// Minimal blocking GET (avoid pulling a new dep: use std + a tiny TCP HTTP/1.0 request).
fn ureq_get(url: &str) -> Result<String, std::io::Error> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = stripped.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((stripped, "/".into()));
    let mut stream = TcpStream::connect(host_port)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

fn extract_peer_id(http_response: &str) -> Option<String> {
    // body after the blank line; find /p2p/<id> in the JSON peers list.
    let body = http_response.split("\r\n\r\n").nth(1).unwrap_or(http_response);
    let idx = body.find("/p2p/")?;
    let rest = &body[idx + 5..];
    let end = rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len());
    let pid = &rest[..end];
    if pid.starts_with("12D3") { Some(pid.to_string()) } else { None }
}

async fn advertise_and_wait_peer(b: &CeClient, a: &CeClient, b_id: &str) {
    // B advertises a probe service; we wait until A can find B (proves the mesh formed).
    let _ = b.advertise_service("pin:host").await;
    for _ in 0..60 {
        let _ = b.advertise_service("pin:host").await;
        if let Ok(found) = a.find_service("pin:host").await {
            if found.iter().any(|p| p == b_id) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Not fatal: discovery may lag; the offer/audit path retries below. But surface a hint.
    eprintln!("WARN: A did not discover B within timeout; continuing (offer retries will cover it)");
}

async fn retry_offer(
    a: &CeClient,
    host: &str,
    caps: &str,
    cid: &str,
    bytes_len: u64,
) -> ce_pin::proto::OfferResp {
    let mut last = None;
    for _ in 0..20 {
        match ce_pin::client::offer(a, host, caps, cid, bytes_len, "1000000000000000", 0).await {
            Ok(r) => return r,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("offer never reached host: {last:?}");
}

fn parse_id(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}
