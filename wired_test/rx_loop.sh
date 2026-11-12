#!/bin/bash
# =============================================================================
# RAIL receiver loop - run on the RECEIVER (B) from your RAIL1 folder:
#     bash wired_test/rx_loop.sh <out_dir> <log_file>      [idle seconds, default 8]
#
# Why: a RAIL receiver that stays up ignores every later sender run. It
# remembers the object numbers it has finished, and each new sender run starts
# its numbers again.
# This loop starts a fresh receiver, lets it stop itself after 8 idle seconds,
# and starts it again. So every sender run meets a new receiver.
# Wait 20 seconds between two send commands on A (the scripts do this).
#
# The screen shows one line per sender run. The full receiver output goes to
# <log_file>. Stop the loop with Ctrl-C when the phase is finished.
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
USAGE="usage: bash wired_test/rx_loop.sh <out_dir> <log_file> [idle_seconds]"
OUT="${1:?$USAGE}"
LOG="${2:?$USAGE}"
IDLE="${3:-8}"
mkdir -p "$OUT" "$(dirname "$LOG")"
[ -f .venv/bin/activate ] && source .venv/bin/activate
TMP=$(mktemp)
runs=0

flush_run() {
  # keep the output of a receiver run only if it handled at least one object
  if grep -q '"status"' "$TMP"; then
    runs=$((runs + 1))
    d=$(grep -c '"status": "DELIVERED"' "$TMP")
    r=$(grep -c '"status": "REJECTED"' "$TMP")
    { echo "=== receiver run $runs ended $(date '+%F %T')  delivered=$d rejected=$r"
      cat "$TMP"; } >> "$LOG"
    echo "[rx $(date +%T)] run $runs: DELIVERED $d  REJECTED $r"
  fi
  : > "$TMP"
}

stop_loop() {
  flush_run
  rm -f "$TMP"
  echo
  echo "[rx] loop stopped after $runs run(s) with objects. Full log: $LOG"
  exit 0
}
trap stop_loop INT TERM

echo "[rx] loop started $(date '+%F %T')  out=$OUT  idle=${IDLE}s  log=$LOG" | tee -a "$LOG"
echo "[rx] waiting for the sender... (one line appears per sender run)"
while true; do
  python3 -u -m railcds.cli receive --out "$OUT" --no-preflight --timeout "$IDLE" > "$TMP" 2>&1
  if grep -q "Address already in use" "$TMP"; then
    echo "[rx] port 52080 is busy: another receiver or iperf is still running."
    echo "     Stop it (Ctrl-C in its terminal), then start this loop again."
    rm -f "$TMP"; exit 1
  fi
  if ! grep -q "listening on" "$TMP"; then
    echo "[rx] the receiver did not start. Its output:"
    tee -a "$LOG" < "$TMP"
    rm -f "$TMP"; exit 1
  fi
  flush_run
done
