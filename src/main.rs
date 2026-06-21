//! `ce-pin` — content-availability / paid blob-pinning over CE.
//!
//! A thin CLI over the [`ce_pin`] library and the CE SDK (`ce-rs`). Run `ce-pin serve` on a host to
//! earn rent by holding content; on a publisher, `ce-pin add <file>` chunks the file into the
//! content-addressed data layer and replicates it to ranked mesh peers, and `ce-pin get <cid>`
//! fetches it back (trustless — every chunk is CID-verified).

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use ce_pin::client as pin_client;
use ce_pin::pinset::{Entry, PinJob, PinSet, Replica};
use ce_pin::{caps, load_roots};
use ce_rs::{Amount, CeClient};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ce-pin",
    version,
    about = "Content-availability / paid blob-pinning over CE — content-addressing is the proof.",
    long_about = None
)]
struct Cli {
    /// CE node HTTP API base URL.
    #[arg(long, default_value = ce_rs::DEFAULT_BASE_URL, global = true)]
    api: String,

    /// Path to the pin-set index file (default: <config dir>/ce-pin/pins.json).
    #[arg(long, global = true)]
    pinset: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Publish a file to the data layer and replicate it to N mesh peers. Prints the object CID.
    Add {
        /// Path to the file to pin.
        file: PathBuf,
        /// Desired number of live replicas.
        #[arg(long, default_value_t = 3)]
        replication: u8,
        /// Rent offered, in credits per GB-hour (e.g. "0.001"). Stored as base units internally.
        #[arg(long, default_value = "0.001")]
        rent: String,
        /// Blocks until rent guarantee expires (0 = node default lifetime semantics on channels).
        #[arg(long, default_value_t = 8640)]
        expiry_blocks: u64,
        /// Optional human label for `ce-pin ls`.
        #[arg(long)]
        label: Option<String>,
        /// Capability chain (hex) to present to hosts; overrides $CE_PIN_CAPS / config file.
        #[arg(long)]
        caps: Option<String>,
        /// Skip replication — just publish to the local data layer and record the CID.
        #[arg(long)]
        no_replicate: bool,
    },
    /// Fetch an object by CID and write it to a file (or stdout-path).
    Get {
        /// The object CID.
        cid: String,
        /// Output path (default: ./<cid>.bin).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// List local pins and their replica health.
    Ls,
    /// Advertise availability of a CID on the DHT (so fetchers can discover this holder).
    Announce {
        /// The object CID to announce.
        cid: String,
    },
    /// Check retrievability of a CID across the mesh: who advertises it, and do they still hold it.
    Status {
        /// The object CID to check.
        cid: String,
        /// Capability chain (hex) for the status probe (hosts gate `pin:read`).
        #[arg(long)]
        caps: Option<String>,
        /// Run a full proof-of-retrievability audit against each holder (beacon-seeded challenge).
        #[arg(long)]
        audit: bool,
    },
    /// Remove a CID from the local pin-set (does not force hosts to drop it).
    Rm {
        /// The object CID to forget.
        cid: String,
    },
    /// Run as a pinning host: accept cap-gated pins, answer audits, earn rent.
    Serve,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let client = CeClient::new(cli.api.clone());
    let pinset_path = cli.pinset.clone().unwrap_or_else(PinSet::default_path);

    match cli.cmd {
        Cmd::Add { file, replication, rent, expiry_blocks, label, caps: caps_arg, no_replicate } => {
            cmd_add(&client, &pinset_path, &file, replication, &rent, expiry_blocks, label, caps_arg.as_deref(), no_replicate).await
        }
        Cmd::Get { cid, out } => cmd_get(&client, &cid, out).await,
        Cmd::Ls => cmd_ls(&pinset_path),
        Cmd::Announce { cid } => cmd_announce(&client, &cid).await,
        Cmd::Status { cid, caps: caps_arg, audit } => cmd_status(&client, &pinset_path, &cid, caps_arg.as_deref(), audit).await,
        Cmd::Rm { cid } => cmd_rm(&pinset_path, &cid),
        Cmd::Serve => ce_pin::host::serve(&client, load_roots()).await,
    }
}

async fn cmd_add(
    client: &CeClient,
    pinset_path: &std::path::Path,
    file: &std::path::Path,
    replication: u8,
    rent_credits: &str,
    expiry_blocks: u64,
    label: Option<String>,
    caps_arg: Option<&str>,
    no_replicate: bool,
) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    // Rent: parse human credit decimals -> base units (integer), stored as a decimal string.
    let rent = Amount::parse_credits(rent_credits)
        .with_context(|| format!("parsing --rent '{rent_credits}' as credits"))?;
    let rent_base = rent.base().to_string();

    let (cid, bytes_len) = pin_client::add_bytes(client, &bytes).await?;
    println!("published {} ({} bytes) -> {cid}", file.display(), bytes_len);

    // Resolve the expiry height relative to the chain tip.
    let expiry_height = match client.status().await {
        Ok(s) if expiry_blocks > 0 => s.height + expiry_blocks,
        _ => 0,
    };

    let mut set = PinSet::load(pinset_path)?;
    let mut replicas: Vec<Replica> = Vec::new();

    if !no_replicate {
        let caps_hex = caps::resolve(caps_arg);
        let candidates = pin_client::candidate_hosts(client).await.unwrap_or_default();
        if candidates.is_empty() {
            eprintln!(
                "no pinning hosts advertised pin:host on the mesh yet — recorded locally; \
                 run `ce-pin announce {cid}` or start hosts with `ce-pin serve`."
            );
        } else {
            match pin_client::replicate(
                client, &cid, bytes_len, &rent_base, expiry_height, replication as usize, &caps_hex, &candidates, &[],
            )
            .await
            {
                Ok(r) => {
                    println!("replicated to {}/{} host(s)", r.len(), replication);
                    replicas = r;
                }
                Err(e) => eprintln!("replication failed: {e} (recorded locally; retry with `ce-pin announce`/hosts up)"),
            }
        }
        // Always announce our own availability of the CID.
        let _ = pin_client::announce(client, &cid).await;
    }

    set.upsert(Entry {
        job: PinJob { cid: cid.clone(), bytes_len, replication, rent_per_gb_hour: rent_base, expiry_height, label },
        replicas,
    });
    set.save(pinset_path)?;
    println!("pin recorded in {}", pinset_path.display());
    Ok(())
}

async fn cmd_get(client: &CeClient, cid: &str, out: Option<PathBuf>) -> Result<()> {
    let bytes = pin_client::get(client, cid).await?;
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{cid}.bin")));
    std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    println!("fetched {cid} ({} bytes) -> {}", bytes.len(), path.display());
    Ok(())
}

fn cmd_ls(pinset_path: &std::path::Path) -> Result<()> {
    let set = PinSet::load(pinset_path)?;
    if set.pins.is_empty() {
        println!("no pins recorded ({})", pinset_path.display());
        return Ok(());
    }
    println!("{:<66}  {:>10}  {:>5}  {:>8}  {}", "CID", "BYTES", "REPL", "HEALTHY", "LABEL");
    for (cid, e) in &set.pins {
        println!(
            "{:<66}  {:>10}  {:>5}  {:>4}/{:<3}  {}",
            cid,
            e.job.bytes_len,
            e.job.replication,
            e.healthy_replicas(),
            e.replicas.len(),
            e.job.label.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

async fn cmd_announce(client: &CeClient, cid: &str) -> Result<()> {
    pin_client::announce(client, cid).await?;
    println!("announced availability of {cid} on the DHT (pin:{cid})");
    Ok(())
}

async fn cmd_status(
    client: &CeClient,
    pinset_path: &std::path::Path,
    cid: &str,
    caps_arg: Option<&str>,
    do_audit: bool,
) -> Result<()> {
    let holders = pin_client::find_replicas(client, cid).await.unwrap_or_default();
    println!("{cid}: {} holder(s) advertised on the DHT", holders.len());
    let caps_hex = caps::resolve(caps_arg);

    // Combine DHT-advertised holders with any we recorded locally.
    let mut all: Vec<String> = holders.clone();
    if let Ok(set) = PinSet::load(pinset_path) {
        if let Some(e) = set.get(cid) {
            for r in &e.replicas {
                if !all.contains(&r.holder) {
                    all.push(r.holder.clone());
                }
            }
        }
    }
    if all.is_empty() {
        println!("  (no holders known — try `ce-pin announce {cid}` or ensure hosts are serving)");
        return Ok(());
    }

    let mut live = 0usize;
    for host in &all {
        let short = &host[..16.min(host.len())];
        if do_audit {
            match pin_client::audit_replica(client, host, &caps_hex, cid).await {
                Ok(true) => {
                    live += 1;
                    println!("  {short}…  PROOF OK (retrievable)");
                }
                Ok(false) => println!("  {short}…  PROOF FAILED (not retrievable)"),
                Err(e) => println!("  {short}…  audit error: {e}"),
            }
        } else {
            match pin_client::probe_status(client, host, &caps_hex, cid).await {
                Ok(s) if s.held => {
                    live += 1;
                    println!("  {short}…  HELD ({} bytes)", s.bytes);
                }
                Ok(_) => println!("  {short}…  not held"),
                Err(e) => println!("  {short}…  unreachable: {e}"),
            }
        }
    }
    println!("retrievable from {live}/{} holder(s)", all.len());

    // Reflect the freshly-measured health back into the pin-set, if we track this CID.
    if let Ok(mut set) = PinSet::load(pinset_path) {
        if let Some(e) = set.get_mut(cid) {
            for r in e.replicas.iter_mut() {
                r.last_proof_ok = all.contains(&r.holder) && live > 0 && holders.contains(&r.holder);
            }
            let _ = set.save(pinset_path);
        }
    }
    Ok(())
}

fn cmd_rm(pinset_path: &std::path::Path, cid: &str) -> Result<()> {
    let mut set = PinSet::load(pinset_path)?;
    match set.remove(cid) {
        Some(_) => {
            set.save(pinset_path)?;
            println!("removed {cid} from the pin-set");
            Ok(())
        }
        None => Err(anyhow!("{cid} is not in the pin-set")),
    }
}

/// Initialize tracing once; level from `$RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}
