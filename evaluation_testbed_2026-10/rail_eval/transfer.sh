#!/usr/bin/env bash
# One transfer run across the wire, with a warm-up handshake so the receiver's
# idle clock never runs during the sender's model load.
#
#   transfer.sh CONFIG OUTDIR IDLE TXARGS...
#     CONFIG   rail.yaml for this run
#     OUTDIR   writable dir for rx.jsonl / tx.jsonl / delivered/
#     IDLE     receiver idle-timeout seconds (wait after the last packet)
#     TXARGS   passed to tx_harness (e.g. --spool DIR | --repeat N | file ...)
#
# Sequence:  tx builds the gateway (loads models) -> writes tx.jsonl.warm
#            rx binds the socket             -> writes rx.jsonl.ready
#            controller touches tx.jsonl.go  -> tx transmits the burst
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$1"; OUT="$2"; IDLE="$3"; shift 3
mkdir -p "$OUT/delivered"
rm -f "$OUT/rx.jsonl.ready" "$OUT/tx.jsonl.warm" "$OUT/tx.jsonl.go"

ip netns exec netA /opt/venvA/bin/python "$HERE/tx_harness.py" \
    --node /opt/railtb/nodeA --config "$CFG" \
    --out "$OUT/tx.jsonl" "$@" > "$OUT/tx.log" 2>&1 &
TXPID=$!
for _ in $(seq 1 400); do
  [ -f "$OUT/tx.jsonl.warm" ] && break
  kill -0 "$TXPID" 2>/dev/null || { echo "tx exited before warm-up:"; tail -3 "$OUT/tx.log"; exit 1; }
  sleep 0.1
done

ip netns exec netB /opt/venvB/bin/python "$HERE/rx_harness.py" \
    --node /opt/railtb/nodeB --config "$CFG" \
    --out "$OUT/rx.jsonl" --outdir "$OUT/delivered" --idle "$IDLE" \
    > "$OUT/rx.log" 2>&1 &
RXPID=$!
for _ in $(seq 1 200); do [ -f "$OUT/rx.jsonl.ready" ] && break; sleep 0.1; done

touch "$OUT/tx.jsonl.go"
wait $TXPID
wait $RXPID
tail -1 "$OUT/rx.jsonl"
