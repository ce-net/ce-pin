#!/usr/bin/env bash
#
# ce-pin killer demo: pin a file on one node, fetch it by CID from another.
#
# Spins up TWO local CE nodes on distinct ports (a publisher and a pinning host), grants the
# publisher a `pin:store` capability rooted at the host, pins a file on the publisher (which
# replicates it to the host over the mesh), then fetches it back BY CID from a fresh client against
# the host node — proving content-availability across the mesh with content-addressed integrity.
#
# Requirements: a `ce` binary on PATH (the CE node) and `ce-pin` built (`cargo build --release`).
# This script is illustrative and defensive: it explains each step and cleans up on exit. Adjust the
# `ce` invocation flags to match your local node CLI if they differ.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CE_PIN="${CE_PIN:-$ROOT/target/release/ce-pin}"
CE="${CE:-ce}"

PUB_PORT=8851
HOST_PORT=8852
PUB_DATA="$(mktemp -d)/pub"
HOST_DATA="$(mktemp -d)/host"
WORK="$(mktemp -d)"
PIDS=()

log() { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }
cleanup() {
  log "cleaning up…"
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK" "$PUB_DATA" "$HOST_DATA" 2>/dev/null || true
}
trap cleanup EXIT

command -v "$CE" >/dev/null || { echo "need a 'ce' node binary on PATH (set \$CE)"; exit 1; }
[ -x "$CE_PIN" ] || { echo "build ce-pin first: cargo build --release"; exit 1; }

# 1. Start two local nodes.
log "starting publisher node on :$PUB_PORT and host node on :$HOST_PORT"
"$CE" start --data-dir "$PUB_DATA"  --api-port "$PUB_PORT"  --no-mine >/dev/null 2>&1 & PIDS+=($!)
"$CE" start --data-dir "$HOST_DATA" --api-port "$HOST_PORT" --no-mine >/dev/null 2>&1 & PIDS+=($!)
sleep 4

PUB_API="http://127.0.0.1:$PUB_PORT"
HOST_API="http://127.0.0.1:$HOST_PORT"

# Node ids + API tokens (the SDK reads <data_dir>/api.token; we export per-invocation).
PUB_ID="$("$CE" id --data-dir "$PUB_DATA")"
HOST_ID="$("$CE" id --data-dir "$HOST_DATA")"
log "publisher = ${PUB_ID:0:16}…  host = ${HOST_ID:0:16}…"

# 2. The HOST grants the PUBLISHER a pin:store capability (signed by the host's own key).
log "host grants publisher a pin:store capability"
CAPS="$("$CE" grant "$PUB_ID" --can pin:store,pin:read,pin:audit --expires 1d --data-dir "$HOST_DATA")"

# 3. Start the pinning host loop on the HOST node.
log "starting 'ce-pin serve' on the host"
CE_API_TOKEN="$(cat "$HOST_DATA/api.token")" \
  "$CE_PIN" --api "$HOST_API" serve >/dev/null 2>&1 & PIDS+=($!)
sleep 2

# 4. Create a file and pin it on the PUBLISHER, replicating to the host.
head -c 2000000 /dev/urandom > "$WORK/dataset.bin"
log "publishing $(wc -c < "$WORK/dataset.bin") bytes from the publisher (replication 1)"
CID="$(CE_API_TOKEN="$(cat "$PUB_DATA/api.token")" CE_PIN_CAPS="$CAPS" \
  "$CE_PIN" --api "$PUB_API" --pinset "$WORK/pins.json" \
  add "$WORK/dataset.bin" --replication 1 --rent 0.001 --caps "$CAPS" \
  | tee /dev/stderr | sed -n 's/.*-> \([0-9a-f]\{64\}\).*/\1/p' | head -1)"
log "object CID = $CID"

# 5. Fetch BY CID from a fresh client pointed at the HOST node — the killer move.
log "fetching by CID from the HOST node (content-availability across the mesh)"
CE_API_TOKEN="$(cat "$HOST_DATA/api.token")" \
  "$CE_PIN" --api "$HOST_API" get "$CID" --out "$WORK/fetched.bin"

# 6. Prove byte-for-byte integrity (content addressing guarantees it).
if cmp -s "$WORK/dataset.bin" "$WORK/fetched.bin"; then
  log "SUCCESS: fetched bytes match the original exactly (CID-verified)."
else
  echo "MISMATCH — fetched bytes differ (this should be impossible with content addressing)"; exit 1
fi

# 7. Audit retrievability across the mesh.
log "running a proof-of-retrievability audit against the holder"
CE_API_TOKEN="$(cat "$PUB_DATA/api.token")" CE_PIN_CAPS="$CAPS" \
  "$CE_PIN" --api "$PUB_API" --pinset "$WORK/pins.json" status "$CID" --caps "$CAPS" --audit || true

log "demo complete."
