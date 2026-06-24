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
        /// Refuse to publish a file larger than this many bytes (guards against accidentally
        /// loading a huge file into memory). Default 4 GiB; set 0 to disable the guard.
        #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024)]
        max_size: u64,
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
    /// Remove a CID from the local pin-set. By default also asks current holders to release it
    /// (closing their rent channels); pass `--local` to only forget it locally.
    Rm {
        /// The object CID to forget.
        cid: String,
        /// Only forget locally; do NOT send pin/release to holders.
        #[arg(long)]
        local: bool,
        /// Capability chain (hex) presented to holders for the release (gates `pin:release`).
        #[arg(long)]
        caps: Option<String>,
    },
    /// Extend the rent lease on a pinned CID across its holders (and top up its expiry locally).
    Renew {
        /// The object CID to renew.
        cid: String,
        /// Additional blocks to extend the lease by (added to the current chain tip).
        #[arg(long, default_value_t = 8640)]
        expiry_blocks: u64,
        /// Optional new rent rate in credits per GB-hour (keeps the existing rate if omitted).
        #[arg(long)]
        rent: Option<String>,
        /// Capability chain (hex) presented to holders (gates `pin:store`).
        #[arg(long)]
        caps: Option<String>,
    },
    /// Run the auto re-replication / repair daemon: periodically audit each pin and re-pin any that
    /// have fallen below their desired replication factor, paying accrued rent on healthy channels.
    Watch {
        /// Seconds between repair passes.
        #[arg(long, default_value_t = 300)]
        interval: u64,
        /// Run a single repair pass and exit (do not loop).
        #[arg(long)]
        once: bool,
        /// Capability chain (hex) presented to hosts for audits/re-replication.
        #[arg(long)]
        caps: Option<String>,
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
        Cmd::Add { file, replication, rent, expiry_blocks, label, caps: caps_arg, no_replicate, max_size } => {
            cmd_add(&client, &pinset_path, &file, replication, &rent, expiry_blocks, label, caps_arg.as_deref(), no_replicate, max_size).await
        }
        Cmd::Get { cid, out } => cmd_get(&client, &cid, out).await,
        Cmd::Ls => cmd_ls(&pinset_path),
        Cmd::Announce { cid } => cmd_announce(&client, &cid).await,
        Cmd::Status { cid, caps: caps_arg, audit } => cmd_status(&client, &pinset_path, &cid, caps_arg.as_deref(), audit).await,
        Cmd::Rm { cid, local, caps: caps_arg } => cmd_rm(&client, &pinset_path, &cid, local, caps_arg.as_deref()).await,
        Cmd::Renew { cid, expiry_blocks, rent, caps: caps_arg } => {
            cmd_renew(&client, &pinset_path, &cid, expiry_blocks, rent.as_deref(), caps_arg.as_deref()).await
        }
        Cmd::Watch { interval, once, caps: caps_arg } => cmd_watch(&client, &pinset_path, interval, once, caps_arg.as_deref()).await,
        Cmd::Serve => ce_pin::host::serve(&client, load_roots()).await,
    }
}

#[allow(clippy::too_many_arguments)]
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
    max_size: u64,
) -> Result<()> {
    // Guard against accidentally loading a huge file into memory before reading it.
    let meta = std::fs::metadata(file).with_context(|| format!("stat {}", file.display()))?;
    if max_size > 0 && meta.len() > max_size {
        return Err(anyhow!(
            "{} is {} bytes, over the --max-size limit of {} bytes (raise it or set 0 to disable)",
            file.display(),
            meta.len(),
            max_size
        ));
    }
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

    // Track the health of EACH holder individually so the write-back is per-replica, not a global
    // "any live" flag (which would mark a failed replica healthy just because a sibling passed).
    let mut healthy_holders: Vec<String> = Vec::new();
    for host in &all {
        let short = &host[..16.min(host.len())];
        if do_audit {
            match pin_client::audit_replica(client, host, &caps_hex, cid).await {
                Ok(true) => {
                    healthy_holders.push(host.clone());
                    println!("  {short}…  PROOF OK (retrievable)");
                }
                Ok(false) => println!("  {short}…  PROOF FAILED (not retrievable)"),
                Err(e) => println!("  {short}…  audit error: {e}"),
            }
        } else {
            match pin_client::probe_status(client, host, &caps_hex, cid).await {
                Ok(s) if s.held => {
                    healthy_holders.push(host.clone());
                    println!("  {short}…  HELD ({} bytes)", s.bytes);
                }
                Ok(_) => println!("  {short}…  not held"),
                Err(e) => println!("  {short}…  unreachable: {e}"),
            }
        }
    }
    println!("retrievable from {}/{} holder(s)", healthy_holders.len(), all.len());

    // Reflect the freshly-measured PER-REPLICA health back into the pin-set, if we track this CID.
    if let Ok(mut set) = PinSet::load(pinset_path) {
        if let Some(e) = set.get_mut(cid) {
            for r in e.replicas.iter_mut() {
                // This replica is healthy iff its OWN probe/audit passed this round.
                r.last_proof_ok = healthy_holders.contains(&r.holder);
            }
            let _ = set.save(pinset_path);
        }
    }
    Ok(())
}

async fn cmd_rm(
    client: &CeClient,
    pinset_path: &std::path::Path,
    cid: &str,
    local_only: bool,
    caps_arg: Option<&str>,
) -> Result<()> {
    let mut set = PinSet::load(pinset_path)?;
    let entry = set.remove(cid).ok_or_else(|| anyhow!("{cid} is not in the pin-set"))?;
    set.save(pinset_path)?;

    if !local_only {
        // Tell each holder to drop the pin and close its rent channel. Best-effort: a holder that is
        // unreachable simply keeps the bytes until its lease expires (the host GCs it).
        let caps_hex = caps::resolve(caps_arg);
        let mut released = 0usize;
        for r in &entry.replicas {
            let short = &r.holder[..16.min(r.holder.len())];
            match pin_client::release(client, r, &caps_hex, cid).await {
                Ok(resp) if resp.released => {
                    released += 1;
                    println!("  {short}…  released");
                    // Close the rent channel by redeeming nothing further (host settles on its side).
                    if !r.channel_id.is_empty() {
                        let _ = client.channel_expire(&r.channel_id).await;
                    }
                }
                Ok(_) => println!("  {short}…  was not holding it"),
                Err(e) => println!("  {short}…  release failed: {e}"),
            }
        }
        println!("released from {released}/{} holder(s)", entry.replicas.len());
    }
    println!("removed {cid} from the pin-set");
    Ok(())
}

async fn cmd_renew(
    client: &CeClient,
    pinset_path: &std::path::Path,
    cid: &str,
    expiry_blocks: u64,
    rent_credits: Option<&str>,
    caps_arg: Option<&str>,
) -> Result<()> {
    let mut set = PinSet::load(pinset_path)?;
    let entry = set.get(cid).cloned().ok_or_else(|| anyhow!("{cid} is not in the pin-set"))?;

    let tip = client.status().await.map(|s| s.height).unwrap_or(0);
    let new_expiry = tip + expiry_blocks;
    // Resolve the (optional) new rent rate to base units.
    let rent_base = match rent_credits {
        Some(c) => Amount::parse_credits(c)
            .with_context(|| format!("parsing --rent '{c}'"))?
            .base()
            .to_string(),
        None => entry.job.rent_per_gb_hour.clone(),
    };
    let caps_hex = caps::resolve(caps_arg);

    let mut renewed = 0usize;
    for r in &entry.replicas {
        let short = &r.holder[..16.min(r.holder.len())];
        match pin_client::renew(client, &r.holder, &caps_hex, cid, new_expiry, &rent_base).await {
            Ok(resp) if resp.renewed => {
                renewed += 1;
                println!("  {short}…  renewed to height {}", resp.expiry_height);
            }
            Ok(resp) => println!("  {short}…  not renewed: {:?}", resp.reason),
            Err(e) => println!("  {short}…  renew failed: {e}"),
        }
    }

    // Update the local lease/rent record.
    if let Some(e) = set.get_mut(cid) {
        e.job.expiry_height = new_expiry;
        e.job.rent_per_gb_hour = rent_base;
        set.save(pinset_path)?;
    }
    println!("renewed {cid} on {renewed}/{} holder(s); lease now to height {new_expiry}", entry.replicas.len());
    Ok(())
}

async fn cmd_watch(
    client: &CeClient,
    pinset_path: &std::path::Path,
    interval_secs: u64,
    once: bool,
    caps_arg: Option<&str>,
) -> Result<()> {
    let caps_hex = caps::resolve(caps_arg);
    if once {
        let report = ce_pin::repair::repair_once(client, pinset_path, &caps_hex).await?;
        println!(
            "repair pass: {} pin(s) checked, {} repaired, {} replica(s) added, {} unhealthy",
            report.pins_checked, report.pins_repaired, report.replicas_added, report.replicas_unhealthy
        );
        return Ok(());
    }
    // Loop until Ctrl-C.
    let cancel = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    ce_pin::repair::watch(
        client,
        pinset_path,
        &caps_hex,
        std::time::Duration::from_secs(interval_secs.max(1)),
        cancel,
    )
    .await
}

/// Initialize tracing once; level from `$RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}
