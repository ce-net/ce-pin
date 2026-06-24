# ce-pin `pin/*` wire protocol

This is the normative contract for the messages a ce-pin **host** (`ce-pin serve`) answers and a
ce-pin **client** (`add` / `status` / `renew` / `rm` / `watch`) sends over the CE mesh. It is a
cross-node contract: any independent implementation of a pinning host or client must follow it.

All messages travel over the CE SDK's directed request/reply transport
(`CeClient::request` / `CeClient::reply`), addressed to a topic under the `pin/` prefix. Payloads are
**JSON**, hex-encoded by the transport. Every request carries a `caps` field — a hex-encoded
`ce-cap` capability chain — which the host authorizes (rooted at its own key or a configured org
root) before honoring the action. Abilities are opaque app strings.

## Topics & abilities

| Topic        | Ability required | Request      | Reply        |
|--------------|------------------|--------------|--------------|
| `pin/offer`  | `pin:store`      | `OfferReq`   | `OfferResp`  |
| `pin/audit`  | `pin:audit`      | `AuditReq`   | `AuditResp`  |
| `pin/status` | `pin:read`       | `StatusReq`  | `StatusResp` |
| `pin/renew`  | `pin:store`      | `RenewReq`   | `RenewResp`  |
| `pin/release`| `pin:release`    | `ReleaseReq` | `ReleaseResp`|

A host that fails authorization, cannot parse a payload, or hits an internal error replies with a
**generic negative object** (`{"accepted":false,"held":false,"released":false,"renewed":false,
"reason":"..."}`) so the caller always receives a structured answer rather than a timeout. Clients
must tolerate the union of fields (all reply structs default their non-`accepted`/`held`/etc fields).

## Messages

### `pin/offer` — ask a host to fetch-and-hold an object

```jsonc
// OfferReq
{ "caps": "<hex chain>", "cid": "<object cid>", "bytes_len": 1048576,
  "rent_per_gb_hour": "<base-unit decimal string>", "expiry_height": 8640 }
// OfferResp
{ "accepted": true, "stored_bytes": 1048576, "reason": null }
```

The host MUST run admission control before fetching: reject `bytes_len` over its max-object-size,
`rent_per_gb_hour` below its minimum, and offers that would exceed its capacity budget — returning
`accepted:false` with a `reason`. It MUST re-check the *actual* fetched size against the max (a
publisher's `bytes_len` is untrusted). On success it records the commitment (CID, real size, rent,
expiry) in its held-set and advertises `pin:<cid>` on the DHT.

### `pin/audit` — proof-of-retrievability challenge

```jsonc
// AuditReq
{ "caps": "...", "cid": "...", "nonce": "<hex>", "chunk_index": 3 }
// AuditResp
{ "proof": "<hex sha256(chunk || nonce)>", "reason": null }
```

The host MUST answer only for a CID in its committed held-set (the H3 gate); otherwise it returns
`proof:null` with `reason:"not held locally"`. The auditor derives `chunk_index` from the public
chain `beacon` hash folded with the CID, so neither side biases it; the `nonce` makes replay
impossible. The proof is `sha256(chunk_bytes || nonce_bytes)`, hex-encoded.

### `pin/status` — cheap liveness

```jsonc
// StatusReq  { "caps": "...", "cid": "..." }
// StatusResp { "held": true, "bytes": 1048576 }
```

### `pin/renew` — extend the rent lease

```jsonc
// RenewReq  { "caps": "...", "cid": "...", "expiry_height": 17280, "rent_per_gb_hour": "" }
// RenewResp { "renewed": true, "expiry_height": 17280, "reason": null }
```

The host renews only a CID it holds, and only ever **extends** the lease (never shortens it). An
empty `rent_per_gb_hour` keeps the existing rate.

### `pin/release` — drop a pin

```jsonc
// ReleaseReq  { "caps": "...", "cid": "..." }
// ReleaseResp { "released": true, "reason": null }
```

## Discovery

- A pinning host advertises the service string `pin:host` (`SERVICE_HOST`) so clients can rank and
  discover it via the DHT (`find_service`).
- A host holding a CID advertises `pin:<cid>` (`service_for(cid)`) so fetchers find replica holders
  without a central tracker. Provider records expire, so hosts re-advertise periodically.

## Versioning & stability

The message shapes above are additive-stable: new optional fields may be added (clients default
absent fields via serde), but field meanings and the topic/ability mapping will not change without a
new topic. The host's on-disk held-set is independently versioned (`held::HELD_SCHEMA_VERSION`).
