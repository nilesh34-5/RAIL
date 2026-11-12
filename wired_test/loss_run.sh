#!/bin/bash
# =============================================================================
# RAIL loss test (experiment E2) - run on the SENDER (A) from your RAIL1 folder:
#     bash wired_test/loss_run.sh          (optional: add <nic>, default eno1)
#
# FIRST start the receiver loop on B and leave it running for the whole test:
#     bash wired_test/rx_loop.sh data/recv_loss results_wired/e2_rx_log.txt
#
# 34 runs x 20 text objects of 256 KiB:
#   coder:   Reed-Solomon and RaptorQ
#   repeat:  each symbol sent once (1) or twice (2)
#   loss:    none, random 10/25/35/45 %, burst (Gilbert-Elliott) 10/25/35/45 %
# Burst loss uses the paper's model: bad state loses every packet, good state
# none, r = 25 % (mean burst of 4 packets), p = L*r/(1-L) for mean loss L.
# The three ML detectors are off for this test only, because it measures
# error correction, not detection. Text files are used so no object is
# quarantined.
# 20 s gap between runs, so the receiver loop on B restarts between runs.
# Takes about 17 minutes.
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
[ -f .venv/bin/activate ] && source .venv/bin/activate
IF="${1:-eno1}"
GAP="${GAP:-20}"
OUT=results_wired/e2_loss_log.txt
mkdir -p results_wired spool_loss

echo "Is the receiver loop running on B?"
echo "   B$ bash wired_test/rx_loop.sh data/recv_loss results_wired/e2_rx_log.txt"
read -r -p "Press Enter when it says 'waiting for the sender'... " _

# keep sudo alive for the whole run (tc needs root)
sudo -v
( while true; do sudo -n true; sleep 50; done ) &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo tc qdisc del dev '"$IF"' root 2>/dev/null' EXIT

# one config per coder and repeat setting (ML detectors off)
python3 - <<'PY'
import yaml, copy
base = yaml.safe_load(open('config/rail.yaml', encoding='utf-8'))
for be in ('reedsolo', 'raptorq'):
    for rep in (1, 2):
        c = copy.deepcopy(base)
        c['fec']['backend'] = be
        c['fec']['repeat'] = rep
        for d in ('ember2024_ml', 'malconv_ml', 'malconvgct_ml'):
            c['inspection']['detectors'][d]['enabled'] = False
        yaml.safe_dump(c, open(f'config/loss_{be}_r{rep}.yaml', 'w', encoding='utf-8'), sort_keys=False)
print('loss configs written')
PY

CONDS=(
  "none_0:loss 0%"
  "rand_10:loss 10%"   "rand_25:loss 25%"   "rand_35:loss 35%"   "rand_45:loss 45%"
  "burst_10:loss gemodel 2.78% 25%"  "burst_25:loss gemodel 8.33% 25%"
  "burst_35:loss gemodel 13.46% 25%" "burst_45:loss gemodel 20.45% 25%"
)

echo "=== loss test start $(date)  nic=$IF  gap=${GAP}s" | tee -a "$OUT"
k=0
for be in reedsolo raptorq; do
  for rep in 1 2; do
    for c in "${CONDS[@]}"; do
      tag="${c%%:*}"; spec="${c#*:}"
      [ "$tag" = none_0 ] && [ "$rep" = 2 ] && continue
      k=$((k + 1))
      name="${be}_r${rep}_${tag}"
      d="spool_loss/$name"; rm -rf "$d"; mkdir -p "$d"
      for i in $(seq -w 1 20); do
        yes "RAIL loss test $name object $i" | head -c 262144 > "$d/L_${name}_$i.txt"
      done
      sudo tc qdisc del dev "$IF" root 2>/dev/null
      if ! sudo tc qdisc add dev "$IF" root netem $spec; then
        echo "[!] tc failed for $name - try: sudo modprobe sch_netem" | tee -a "$OUT"; exit 1
      fi
      echo "=== run $k/34  $name | netem $spec | $(date +%T)" | tee -a "$OUT"
      python3 -u -m railcds.cli --config "config/loss_${be}_r${rep}.yaml" send --spool "$d" --no-preflight 2>&1 \
        | grep -E '"object"|"status"|"symbols_sent"|"fec_backend"|Error|error' >> "$OUT"
      sudo tc qdisc del dev "$IF" root
      sleep "$GAP"
    done
  done
done
echo "ALL LOSS RUNS DONE $(date +%T)" | tee -a "$OUT"
echo "Now on B: wait until its last [rx] line appears, Ctrl-C the loop, then run count_loss.sh"
