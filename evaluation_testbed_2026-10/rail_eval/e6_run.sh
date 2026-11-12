#!/usr/bin/env bash
# E6 controller: for each attack, run a fresh receiver session in netB and the
# tamper sender in netA, then count delivered vs detected from rx.jsonl.
# Also tests two audit-log attacks in-process (log entry edit; log tail
# truncation) using AuditLog.verify_chain.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:?usage: e6_run.sh OUTDIR [N]}"; N="${2:-20}"
CFG="$HERE/../configs/e_reedsolo.yaml"
mkdir -p "$OUT"
bash "$HERE/../testbed/net_up.sh" >/dev/null 2>&1
bash "$HERE/../testbed/loss_ctl.sh" none >/dev/null 2>&1
: > "$OUT/e6.jsonl"

for attack in baseline bitflip chunk_swap split_merge truncation forged_sig replay; do
  d="$OUT/$attack"; mkdir -p "$d/delivered"
  rm -f "$d/warm" "$d/go" "$OUT/rx.ready"
  ip netns exec netA /opt/venvA/bin/python "$HERE/e6_tamper.py" \
      --node /opt/railtb/nodeA --config "$CFG" --host 10.20.0.20 --port 52080 \
      --attack "$attack" --n "$N" --warm "$d/warm" --go "$d/go" > "$d/tx.log" 2>&1 &
  TX=$!
  for _ in $(seq 1 200); do [ -f "$d/warm" ] && break; sleep 0.1; done
  ip netns exec netB /opt/venvB/bin/python "$HERE/rx_harness.py" \
      --node /opt/railtb/nodeB --config "$CFG" --out "$d/rx.jsonl" \
      --outdir "$d/delivered" --idle 6 > "$d/rx.log" 2>&1 &
  RX=$!
  for _ in $(seq 1 200); do [ -f "$d/rx.jsonl.ready" ] && break; sleep 0.1; done
  touch "$d/go"
  wait $TX; wait $RX
  python3 - "$OUT/e6.jsonl" "$d/rx.jsonl" "$attack" "$N" <<'PY'
import json, sys, pathlib
out, rxf, attack, n = sys.argv[1:5]; n=int(n)
rows=[json.loads(l) for l in pathlib.Path(rxf).read_text().splitlines()] if pathlib.Path(rxf).exists() else []
delivered=sum(1 for r in rows if r.get("status")=="DELIVERED")
rejected=sum(1 for r in rows if r.get("status")=="REJECTED")
sent = n*2 if attack=="replay" else n
# For replay: n legit + n replays; expect n delivered, n detected(rejected).
if attack=="baseline":
    detected = sent-delivered; expect_delivered=n
elif attack=="replay":
    detected = sent-delivered; expect_delivered=n
else:
    detected = sent-delivered; expect_delivered=0
rate = 100.0*detected/ (sent-expect_delivered if attack in("baseline",) else (n if attack=="replay" else sent)) if True else 0
row={"attack":attack,"objects_sent":sent,"delivered":delivered,"rejected_at_S5":rejected,
     "not_delivered":sent-delivered,
     "detected_pct": (0.0 if attack=="baseline" else 100.0*(sent-delivered)/(n if attack=="replay" else sent))}
open(out,"a").write(json.dumps(row)+"\n")
print(f"{attack:12s} sent={sent:3d} delivered={delivered:3d} rejectedS5={rejected:3d} "
      f"not_delivered={sent-delivered:3d}  detected={row['detected_pct']:.0f}%")
PY
done

# ---- audit-log attacks, in-process against AuditLog --------------------------
/opt/venvA/bin/python - "$OUT/e6.jsonl" <<'PY'
import json, sys, tempfile, os, pathlib
sys.path.insert(0,"/opt/railtb/nodeA")
from railcds.auditlog import AuditLog
out=sys.argv[1]
def fresh():
    p=pathlib.Path(tempfile.mkdtemp())/"log.jsonl"
    lg=AuditLog(p,side="sender")
    for i in range(20):
        lg.append({"ts":i,"epoch":f"e{i}","object_name":f"o{i}","object_size":100,
                   "band":1,"merkle_root":"%064x"%i,"signature":"ab","side":"sender"})
    return p
# (a) edit a historical entry -> chain must break
p=fresh(); lines=p.read_text().splitlines()
rec=json.loads(lines[5]); rec["object_size"]=999; lines[5]=json.dumps(rec,separators=(",",":"),sort_keys=True)
p.write_text("\n".join(lines)+"\n")
broken=AuditLog(p,side="x").verify_chain()
edit_detected = broken is not None
# (b) truncate the tail (remove last 3 entries) -> chain of the remaining prefix
#     still verifies, so truncation is NOT detected without an external anchor
p=fresh(); lines=p.read_text().splitlines(); p.write_text("\n".join(lines[:-3])+"\n")
trunc_detected = AuditLog(p,side="x").verify_chain() is not None
for name,det,note in [("log_entry_edit",edit_detected,"hash-chain link broken"),
    ("log_tail_truncation",trunc_detected,"prefix still self-consistent; needs ledger anchor")]:
    open(out,"a").write(json.dumps({"attack":name,"detected_by_chain":bool(det),
        "detected_pct":100.0 if det else 0.0,"note":note})+"\n")
    print(f"{name:20s} detected_by_hash_chain={det}  ({note})")
PY
echo "[E6] done -> $OUT/e6.jsonl"
