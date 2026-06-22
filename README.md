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
ce-pin add <file> [--replication N] [--rent 0.001] [--label L] [--caps <hex>]   # publish + replicate; prints CID
ce-pin get <cid> [-o out]                                                        # fetch by CID (trustless, CID-verified)
ce-pin ls                                                                        # local pins + replica health
ce-pin announce <cid>                                                            # advertise availability on the DHT
ce-pin status <cid> [--caps <hex>] [--audit]                                     # who holds it / is it retrievable
ce-pin rm <cid>                                                                  # forget a pin locally
ce-pin serve                                                                     # run as a pinning host (earn rent)
```

Global flags: `--api <url>` (node API base) and `--pinset <path>` (the index file).

### What each command does (mapped to CE primitives)

| Command | CE primitives used |
|---|---|
| `add` | `put_object` (chunk → blobs → manifest CID), `atlas` + `history` (rank hosts), `pin/offer` over `request`/`reply` (cap-gated), `advertise_service("pin:<cid>")` |
| `get` | `get_object` (resolve manifest, pull + **CID-verify** every chunk, reassemble) |
| `announce` | `advertise_service("pin:<cid>")` on the DHT |
| `status` | `find_service("pin:<cid>")` + `pin/status` probe, or `--audit` → beacon-seeded proof-of-retrievability over `pin/audit` |
| `serve` | `messages`/`reply` loop, `ce-cap authorize`, `get_object` to hold, `advertise_service`, answers `pin/audit` |

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
**payment channels** (`channel_open` / `sign_receipt` / `channel_close`) so high-frequency
micropayments never touch the chain per unit. The MVP records rent terms and the channel slot on
each replica; wiring the periodic receipt loop end-to-end is the first follow-up (see below).

## Proof-of-retrievability (PoR)

`ce-pin status <cid> --audit` challenges each holder: the auditor derives a chunk index from the
public `beacon` hash (the PoW tip — unbiasable) folded with the CID, sends a fresh random nonce,
and the host must return `sha256(chunk_bytes || nonce)`. The auditor independently fetches and
**CID-verifies** that chunk, recomputes the expected proof, and compares. A host that discarded
the bytes cannot answer; a recorded old proof cannot be replayed (the nonce changes each round).

**Residual trust:** PoR raises the cost of lying but a host colluding with its own challenger is
not structurally prevented — content-addressing guarantees *integrity*, not *availability*. This
is the documented residual assumption from the portfolio spec.

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
├── main.rs       # CLI dispatch (add/get/ls/announce/status/rm/serve)
├── proto.rs      # pin/* wire protocol (offer/audit/status/release) + abilities + service strings
├── pinset.rs     # the cid -> PinJob + replicas index, persisted as JSON
├── placement.rs  # pure host ranking (atlas capacity + on-chain history reputation)
├── audit.rs      # pure proof-of-retrievability (beacon-seeded, replay-resistant)
├── client.rs     # publish / fetch / discover / replicate / audit (wraps ce-rs + proto)
├── host.rs       # serve(): cap-gated pinning host loop
└── caps.rs       # resolving the ce-cap chain the client presents
```

No node changes. Pure SDK app, exactly like `swarm` / `rdev`.

## Status / follow-ups

- Implemented: chunked publish (`put_object`), fetch-by-CID, DHT announce/discover, ranked
  replication to N peers (cap-gated), beacon-seeded PoR audit, the pinning host loop, the pin-set
  index, and the two-node demo.
- TODO (explicit): wire the periodic payment-channel receipt loop for rent (open channel per
  replica in `add`, `sign_receipt` per GB-hour, `channel_close` redemption on the host); the
  auto re-replication loop on a failed audit (the pieces — `audit_replica`, `replicate` with an
  `exclude` set — are present; the long-running daemon that ties them together is the next step);
  and a `--watch`/daemon mode. These are noted in the source.
