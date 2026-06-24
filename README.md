# ce-pin

**Content-availability / paid blob-pinning over CE.** An IPFS-style pinning service with
*payments, capability-gated privacy, and proof-of-retrievability* — built entirely on CE
primitives via the `ce-rs` SDK. ce-pin is an **application on CE**, not a node feature: the node
stays primitives-only (identity, mesh transport, the content-addressed blob layer, the economy,
the `ce-cap` verifier). ce-pin is the policy and UX on top.

> The killer property: **content-addressing IS the integrity proof.** An object's CID is the hash
> of its manifest, and `get_object` re-verifies every chunk against its CID on the way in, so a
> pinning host can never serve bytes the publisher did not pin — and the store cannot be poisoned.

## Install / build

```bash
cargo build --release      # produces target/release/ce-pin
cargo test                 # unit + integration tests (no node required)
```

`ce-pin` depends on `ce-rs` (by path, `../ce-rs`) and `ce-cap` (by path, `../ce/crates/ce-cap`).
It talks to a **local** CE node's HTTP API (default `http://127.0.0.1:8844`) for all blob, mesh,
discovery, and economy operations.

## CLI

```
ce-pin add <file> [--replication N] [--rent 0.001] [--label L] [--caps <hex>] [--max-size BYTES]
                                                                                # publish + replicate; opens rent channels; prints CID
ce-pin get <cid> [-o out]                                                        # fetch by CID (trustless, CID-verified)
ce-pin ls                                                                        # local pins + replica health
ce-pin announce <cid>                                                            # advertise availability on the DHT
ce-pin status <cid> [--caps <hex>] [--audit]                                     # who holds it / is it retrievable (per-replica)
ce-pin renew <cid> [--expiry-blocks N] [--rent C] [--caps <hex>]                 # extend the rent lease across holders
ce-pin watch [--interval SECS] [--once] [--caps <hex>]                           # auto-repair: re-pin under-replicated pins, pay rent
ce-pin rm <cid> [--local] [--caps <hex>]                                         # forget a pin; by default also releases it on holders
ce-pin serve                                                                     # run as a pinning host (earn rent)
```

Global flags: `--api <url>` (node API base) and `--pinset <path>` (the index file).

### Host configuration (`ce-pin serve`)

A pinning host enforces admission control and a disk budget so it is never a DoS target. All limits
are env-tunable (defaults in parentheses):

| Env var | Meaning |
|---|---|
| `CE_PIN_MAX_OBJECT_BYTES` | reject any single object larger than this (2 GiB) |
| `CE_PIN_CAPACITY_BYTES` | total disk budget for held content; GC evicts to stay under it (64 GiB) |
| `CE_PIN_MIN_RENT` | minimum accepted rent, base units / GB-hour; below this is declined (0) |
| `CE_PIN_MAX_CONCURRENT` | `pin/*` requests served in parallel (8) |
| `CE_PIN_FETCH_TIMEOUT_SECS` | per-offer object-fetch timeout (180) |
| `CE_PIN_SEEN_WINDOW` | bounded de-dup window for reply tokens (65536) |
| `CE_PIN_DIR` | where the host stores `held.json` / the client stores `pins.json` / `caps` |

### What each command does (mapped to CE primitives)

| Command | CE primitives used |
|---|---|
| `add` | `put_object` (chunk → blobs → manifest CID), `atlas` + `history` (rank hosts, fault-domain spread), `pin/offer` over `request`/`reply` (cap-gated), `channel_open` (rent), `advertise_service("pin:<cid>")` |
| `get` | `get_object` (resolve manifest, pull + **CID-verify** every chunk, reassemble) |
| `announce` | `advertise_service("pin:<cid>")` on the DHT |
| `status` | `find_service("pin:<cid>")` + `pin/status` probe, or `--audit` → beacon-seeded proof-of-retrievability over `pin/audit`; writes **per-replica** health back |
| `renew` | `pin/renew` over `request`/`reply` (extend lease across holders) |
| `watch` | periodic `pin/audit` of every replica + `replicate(exclude=healthy)` to restore the factor + `sign_receipt` to pay rent |
| `rm` | `pin/release` to holders + `channel_expire` to settle, then forget locally |
| `serve` | `messages`/`reply` loop on a bounded worker pool, `ce-cap authorize`, admission control + capacity GC, `get_object` to hold, `advertise_service`, answers `pin/offer`/`audit`/`status`/`renew`/`release` |

## Trust model (capability-only)

Authorization is CE's single primitive. Every host action verifies a **signed, attenuating
`ce-cap` chain** rooted at the host's own key or a configured org root before acting — the same
`authorize(...)` call the node and `rdev` use. Abilities are opaque app strings:

- `pin:store` — a host accepts a pin from a holder of this.
- `pin:read` — a host serves *private* (cap-gated) content to a holder of this.
- `pin:audit` — answer a proof-of-retrievability challenge.
- `pin:release` — drop a pin.

A `pin:read` cap cannot perform `pin:store` (attenuation is enforced; see the integration tests).

The client presents its chain via `--caps <hex>`, `$CE_PIN_CAPS`, or `<config>/ce-pin/caps`.
A host loads its accepted roots from `$CE_PIN_ROOTS`, else `$CE_DATA_DIR/roots`, else
`~/.local/share/ce/roots` (one 64-hex NodeId per line). With no roots file, only self-issued
chains are honored.

Produce a chain out-of-band, e.g. on the host or org root:

```bash
ce grant <publisher-node-id> --can pin:store,pin:read,pin:audit --expires 30d
```

## Money model

Rent is priced in **integer base units** (1 credit = 10^18 base units, wei-style) and carried as
**decimal strings** — never floats. The CLI accepts human credit decimals for `--rent` (e.g.
`0.001`) and converts to base units via `ce_rs::Amount`. Per-GB-hour rent is settled with CE
**payment channels** (`channel_open` / `sign_receipt` / `channel_close`):

- **`add`** opens a payment channel to each accepting host (when `--rent > 0` and a lease length is
  set), sizing the locked capacity to the estimated rent over the lease, and records the real
  `channel_id` on the replica — not a placeholder.
- **`watch`** signs a rising cumulative receipt per healthy replica each pass (`pay_rent`), so the
  host accrues GB-hours it can redeem. The owed amount is computed with **integer milli-GB math**
  (`rent_owed_base`) so money never rides a float.
- **`rm`** / lease expiry settle the channel (`channel_expire`); a host redeems the highest receipt
  via `channel_close` on its side.

A host that wants real pricing sets `CE_PIN_MIN_RENT` and declines zero-rent offers.

## Proof-of-retrievability (PoR)

`ce-pin status <cid> --audit` challenges each holder: the auditor derives a chunk index from the
public `beacon` hash (the PoW tip — unbiasable) folded with the CID, sends a fresh random nonce,
and the host must return `sha256(chunk_bytes || nonce)`. The auditor independently fetches and
**CID-verifies** that chunk, recomputes the expected proof, and compares. A host that discarded
the bytes cannot answer; a recorded old proof cannot be replayed (the nonce changes each round).

**Held-set gate (closes the obvious forgery).** The host answers a PoR challenge for a CID *only if
it is in the host's authoritative committed held-set*. Without this gate a host that discarded the
bytes could exploit the SDK's `get_blob` mesh-refetch fallback to **re-pull the challenged chunk
from a sibling replica and forge a passing proof** — proving availability-somewhere, not
retrievability-on-this-host. The gate fails the audit for any un-held CID (never pinned, released,
or GC-evicted) *before any blob read*, so a sibling's copy can never satisfy our challenge. (See the
H3 regression test in `tests/live_mesh.rs` and the unit tests in `src/host.rs`.)

**Residual trust (named):** the gate stops a host from forging a proof for a CID it never committed
to. It does **not** yet prove *byte-level* local possession for a held-but-garbage-collected CID,
because the node's `GET /blobs/:hash` always falls back to a mesh fetch on a local miss (ignoring
query params), so an app cannot force a no-mesh byte read. The sound fix is a node-side local-only
read (`?local=1` → 404 on a local miss) surfaced as `CeClient::get_blob_local`; **this is deferred
on the node team** and called out in `src/host.rs::do_audit`. Until then, content-addressing
guarantees *integrity*, and the held-set gate is the strictest *availability* enforcement an app can
do from outside the node.

## Killer demo

`examples/demo.sh` spins up two local CE nodes (a publisher and a pinning host), grants the
publisher a `pin:store` capability rooted at the host, pins a random 2 MB file on the publisher
(which replicates it to the host over the mesh), then **fetches it back by CID from the host
node** and proves byte-for-byte integrity, finishing with a PoR audit. Run it with a `ce` node
binary on `PATH`:

```bash
cargo build --release
./examples/demo.sh
```

On Windows (or any platform with PowerShell 7+), run the cross-platform equivalent:

```powershell
cargo build --release
pwsh examples/demo.ps1
```

## Architecture

```
src/
├── lib.rs        # crate docs + load_roots()
├── main.rs       # CLI dispatch (add/get/ls/announce/status/renew/watch/rm/serve)
├── proto.rs      # pin/* wire protocol (offer/audit/status/renew/release) + abilities + service strings
├── pinset.rs     # the cid -> PinJob + replicas index, persisted atomically as JSON
├── placement.rs  # pure host ranking (atlas capacity + history reputation) + fault-domain spread
├── audit.rs      # pure proof-of-retrievability (beacon-seeded, replay-resistant)
├── config.rs     # host admission/capacity config (size/rent/capacity/concurrency, env-tunable)
├── held.rs       # host held-set: byte accounting, expiry, GC/eviction, atomic + corruption-safe save
├── metrics.rs    # host counters (offers/audits/evictions) for observability
├── client.rs     # publish / fetch / discover / replicate / rent / renew / release / audit
├── repair.rs     # auto re-replication (watch): audit -> repair_plan -> replicate -> pay rent
├── host.rs       # serve(): cap-gated host loop — admission, GC, bounded concurrency, timeouts
└── caps.rs       # resolving the ce-cap chain the client presents
```

No node changes. Pure SDK app, exactly like `swarm` / `rdev`.

## Status / what's implemented

- **Content**: chunked publish (`put_object`), fetch-by-CID (CID-verified), DHT announce/discover.
- **Placement**: reputation-ranked + **fault-domain-diverse** replication to N peers (cap-gated),
  spreading replicas across distinct `region:`/`zone:`/`asn:` tags so one datacenter loss is not fatal.
- **Rent**: real payment channels — `add` opens one per replica, `watch` signs rising GB-hour
  receipts (integer money), `rm`/expiry settle.
- **Availability**: beacon-seeded PoR audit with the held-set gate (closes the obvious forgery),
  per-replica health write-back, and a **`watch` repair daemon** that re-pins under-replicated content.
- **Lifecycle**: `renew` extends leases; `rm` releases on holders; hosts enforce **expiry** and GC.
- **Host robustness**: admission control (size/rent/capacity), capacity accounting + eviction
  (expired → lowest-rent → LRU), bounded-concurrency request handling, per-offer fetch timeouts,
  a bounded de-dup window, atomic + corruption-safe persistence, and metrics.

## Deferred (honestly)

- **Byte-level local-only PoR** for a held-but-GC'd CID — needs a node-side `get_blob_local`
  (`GET /blobs/:hash?local=1` → 404 on local miss). Tracked in `src/host.rs::do_audit`; the held-set
  gate is the strongest app-side enforcement until then.
- **Encrypted-at-rest / read-gated private content** — `pin:read` gates the `pin/status` probe, but
  the blob store itself is open; true private serving needs encryption-at-rest (not yet implemented).
- **Recursive / directory pinning** — `add` takes a single file; a manifest-of-manifests for whole
  directories is future work.
- **Streaming reads for very large files** — `get` buffers the whole object in memory (the `--max-size`
  guard bounds `add`); chunk-streaming I/O is deferred.
