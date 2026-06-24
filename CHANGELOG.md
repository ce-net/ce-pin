# Changelog

All notable changes to `ce-pin` are documented here. The `pin/*` wire protocol (see `src/proto.rs`)
is a cross-node contract; protocol-affecting changes are called out explicitly.

## [Unreleased] — hardening + feature wave

### Added
- **Host admission control** (`config::HostConfig`): reject offers above `CE_PIN_MAX_OBJECT_BYTES`,
  below `CE_PIN_MIN_RENT` (base units / GB-hour), or that would exceed `CE_PIN_CAPACITY_BYTES`. The
  declared size is checked before fetching and the actual fetched size is re-checked after, so a
  lying `bytes_len` cannot smuggle a large object past the size gate.
- **Capacity accounting + garbage collection** (`held::HeldSet`): per-CID byte/rent/expiry records;
  a background GC loop drops expired leases and evicts (expired → lowest-rent → LRU) to stay under
  the disk budget.
- **Payment-channel rent** (`client`): `add` opens a channel per accepting host (real `channel_id`,
  not a placeholder); `watch` signs rising GB-hour receipts (`pay_rent`, integer money); `rm`/expiry
  settle. `rent_owed_base` computes owed amounts with integer milli-GB math (never a float).
- **Auto re-replication daemon** `ce-pin watch` (`repair`): periodically audits every replica and
  re-pins under-replicated content (`repair_plan` + `replicate(exclude=healthy)`), paying rent.
  `--once` runs a single pass; the loop shuts down cleanly on Ctrl-C.
- **Lease lifecycle**: `pin/renew` protocol message + `ce-pin renew` (extend the lease across holders),
  host-side expiry enforcement, and `ce-pin rm` now releases pins on holders (`pin/release`) and
  settles their channels unless `--local`.
- **Fault-domain-aware placement** (`placement`): replicas are spread across distinct
  `region:`/`zone:`/`asn:` atlas tags so one datacenter/ASN failure cannot take out every copy.
- **Host metrics** (`metrics::HostMetrics`): offers accepted/declined/failed, audits passed/failed,
  GC evictions, auth denials — logged periodically by `serve`.
- **`--max-size` guard** on `add` to bound the in-memory read of the published file.
- Runnable example `examples/grant_chain.rs` (the ce-cap grant/authorize/attenuation workflow,
  offline) and doctests on `audit::prove`, `placement::rank`, `pinset::Entry::healthy_replicas`.

### Changed (protocol)
- New `pin/renew` request/reply (`RenewReq`/`RenewResp`). Existing `pin/offer`/`audit`/`status`/
  `release` messages are unchanged on the wire; `OfferResp` gains no required fields.
- The held-set on-disk format is now versioned (`held::HELD_SCHEMA_VERSION`); the legacy v0
  `{ "cids": [...] }` file is migrated forward on load.

### Robustness
- `serve` now handles `pin/*` requests on a bounded worker pool (`CE_PIN_MAX_CONCURRENT`) instead of
  a single sequential task, removing head-of-line blocking; each offer fetch has a timeout
  (`CE_PIN_FETCH_TIMEOUT_SECS`).
- The de-dup reply-token window is bounded (`CE_PIN_SEEN_WINDOW`, FIFO eviction) — no more unbounded
  memory growth on a long-lived host.
- Held-set and pin-set are persisted atomically (temp file + fsync + rename); a corrupt held-set is
  moved aside and surfaced rather than silently dropping every commitment.
- On-chain revocation is refreshed periodically inside `serve` so a revoked capability stops
  authorizing within ~10s.
- PoR audit no longer auto-passes a zero-chunk (empty) object; `status` writes per-replica health
  (each replica's own probe/audit result), not a global "any live" flag.

### Security
- The PoR held-set gate (finding H3) is retained and documented: a host answers a challenge only for
  a CID in its committed held-set, so a discarded-then-refetched sibling copy cannot forge a proof.
  Byte-level local-only PoR remains deferred on a node-side `get_blob_local` (see README "Deferred").
