#!/usr/bin/env bash
# E2 - one-way reliability under packet loss (no acknowledgements).
#
# For each (loss model, loss rate, FEC backend, block repetition) the sender
# transmits a batch of fixed-size objects across the wire; the wire drops
# packets with loss_wire.c (Bernoulli "random" or Gilbert-Elliott "ge").
# We record delivery ratio D (objects delivered intact / sent) and FEC overhead
# eta = (bytes sent - object bytes)/object bytes. Each point repeated REPS times.
#
# Reliability is a property of S4/FEC and the link, not of the detectors, so a
# lightweight inspection config (fast_inspect.yaml: structural+YARA+entropy
# only) is used to keep run time sane. Detection accuracy is measured with ALL
# detectors in E5. The wire is built once.
#
#   e2_reliability.sh OUTDIR [REPS] [NOBJ]
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFGDIR="$HERE/../configs"
OUT="${1:?usage: e2_reliability.sh OUTDIR [REPS] [NOBJ] [BACKENDS]}"; REPS="${2:-5}"; NOBJ="${3:-20}"
BACKENDS="${4:-reedsolo raptorq}"
mkdir -p "$OUT"; OBJDIR="$OUT/objs"; mkdir -p "$OBJDIR"
for i in $(seq 1 "$NOBJ"); do [ -f "$OBJDIR/obj_$i.bin" ] || head -c 262144 /dev/urandom > "$OBJDIR/obj_$i.bin"; done

bash "$HERE/../testbed/net_up.sh" >/dev/null 2>&1     # wire built ONCE
touch "$OUT/e2.jsonl"

mkcfg() { # backend repeat -> path
  local cfg="$OUT/cfg_$1_r$2.yaml"
  python3 - "$CFGDIR/fast_inspect.yaml" "$cfg" "$1" "$2" <<'PY'
import sys
inp, outp, backend, repeat = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
s=open(inp).read()
s=s.replace('backend: "auto"', f'backend: "{backend}"')
s=s.replace('repeat: 1', f'repeat: {repeat}')
open(outp,'w').write(s)
PY
  echo "$cfg"
}

run_point() { # model rate backend repeat rep
  local model="$1" rate="$2" backend="$3" repeat="$4" rep="$5"
  case "$model" in
    none)   bash "$HERE/../testbed/loss_ctl.sh" none >/dev/null 2>&1 ;;
    random) bash "$HERE/../testbed/loss_ctl.sh" random "$rate" >/dev/null 2>&1 ;;
    ge)     bash "$HERE/../testbed/loss_ctl.sh" ge "$rate" 4 >/dev/null 2>&1 ;;
  esac
  local cfg; cfg=$(mkcfg "$backend" "$repeat")
  local d="$OUT/run_${model}_${rate}_${backend}_r${repeat}_${rep}"
  bash "$HERE/transfer.sh" "$cfg" "$d" 3 --spool "$OBJDIR" >/dev/null 2>&1
  python3 - "$OUT/e2.jsonl" "$d" "$model" "$rate" "$backend" "$repeat" "$rep" "$NOBJ" <<'PY'
import json, sys, pathlib
out, dd, model, rate, backend, repeat, rep, nobj = sys.argv[1:9]
d=pathlib.Path(dd); delivered=0; sent_sym=0; obj_bytes=0
rx=[json.loads(l) for l in (d/"rx.jsonl").read_text().splitlines()] if (d/"rx.jsonl").exists() else []
tx=[json.loads(l) for l in (d/"tx.jsonl").read_text().splitlines()] if (d/"tx.jsonl").exists() else []
for r in rx:
    if r.get("status")=="DELIVERED": delivered+=1
for t in tx:
    if t.get("status")=="SENT":
        obj_bytes+=t.get("size",0); sent_sym+=t.get("symbols_sent",0)
sent_bytes=sent_sym*(1024+25)
row={"model":model,"rate":float(rate),"backend":backend,"repeat":int(repeat),
     "rep":int(rep),"n_objects":int(nobj),"delivered":delivered,
     "delivery_ratio":delivered/int(nobj),
     "fec_overhead_eta":(sent_bytes-obj_bytes)/obj_bytes if obj_bytes else None}
open(out,"a").write(json.dumps(row)+"\n")
eta=row["fec_overhead_eta"]
print(f"{model:6s} loss={float(rate)*100:4.0f}% {backend:8s} rep{repeat} #{rep}  D={delivered}/{nobj}  eta={eta:.2f}" if eta is not None else f"{model} {rate} {backend} empty")
PY
}

for backend in $BACKENDS; do
  for rep in $(seq 1 "$REPS"); do run_point none 0.0 "$backend" 1 "$rep"; done
  for model in random ge; do
    for rate in 0.10 0.25 0.35 0.45; do
      for repeat in 1 2; do
        for rep in $(seq 1 "$REPS"); do run_point "$model" "$rate" "$backend" "$repeat" "$rep"; done
      done
    done
  done
done
echo "[E2] done -> $OUT/e2.jsonl ($(wc -l < "$OUT/e2.jsonl") points)"
