#!/bin/bash
# =============================================================================
# RAIL speed test (experiment E8) - run on the SENDER (A) from your RAIL1 folder:
#     bash wired_test/speed_run.sh
#
# FIRST start the receiver loop on B:
#     bash wired_test/rx_loop.sh data/recv_speed results_wired/e8_rx_log.txt
#
# Sends three 10 MiB text files with inspection on (all 7 detectors), then the
# same three with the ML detectors off. Waits 20 s between runs so the
# receiver loop restarts. Each run's output and its "real" time go to
# results_wired/e8_rail_full_N.txt and e8_rail_noml_N.txt, and a one-line
# summary per run goes to results_wired/e8_summary.txt.
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
[ -f .venv/bin/activate ] && source .venv/bin/activate
GAP="${GAP:-20}"
mkdir -p spool_speed results_wired
for i in 1 2 3; do
  [ -f spool_speed/big$i.txt ] || yes "speed test line" | head -c 10485760 > spool_speed/big$i.txt
done
[ -f config/speed_noml.yaml ] || python3 wired_test/make_noml_config.py

echo "Is the receiver loop running on B?"
echo "   B$ bash wired_test/rx_loop.sh data/recv_speed results_wired/e8_rx_log.txt"
read -r -p "Press Enter when it says 'waiting for the sender'... " _

SUM=results_wired/e8_summary.txt
echo "=== speed test $(date '+%F %T')  gap=${GAP}s" | tee -a "$SUM"
for mode in full noml; do
  for i in 1 2 3; do
    out="results_wired/e8_rail_${mode}_$i.txt"
    if [ "$mode" = full ]; then cfg=""; else cfg="--config config/speed_noml.yaml"; fi
    echo "--- $mode run $i started $(date +%T) (inspection $([ $mode = full ] && echo on || echo off))"
    { time python3 -u -m railcds.cli $cfg send "spool_speed/big$i.txt" --no-preflight ; } > "$out" 2>&1
    real=$(grep -E '^real' "$out" | awk '{print $2}')
    st=$(grep -m1 '"status"' "$out" | tr -d ' ,"' | sed 's/status://')
    echo "$mode run $i: real=$real status=$st" | tee -a "$SUM"
    sleep "$GAP"
  done
done
echo "ALL SPEED RUNS DONE $(date +%T)" | tee -a "$SUM"
echo "Now on B: wait for the 6th [rx] line, then Ctrl-C the loop."
