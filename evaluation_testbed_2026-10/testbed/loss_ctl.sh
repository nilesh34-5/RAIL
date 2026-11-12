#!/usr/bin/env bash
# Set the loss model on the wire (egress of netW:wB, i.e. frames heading to G_B).
#   loss_ctl.sh none
#   loss_ctl.sh random <loss_fraction>               e.g. random 0.10
#   loss_ctl.sh ge <mean_loss> <mean_burst_len>      e.g. ge 0.10 4
#   loss_ctl.sh counters                             -> "seen dropped"
# Gilbert-Elliott parameters: loss 100% in Bad, 0% in Good (simple Gilbert),
#   r = 1/mean_burst_len,  p = L*r/(1-L)   so that the mean loss equals L.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJ=/tmp/loss_wire.o
MODE="${1:?mode}"
u32() { python3 -c "import sys; v=float(sys.argv[1]); print(min(int(round(v*4294967296)),4294967295))" "$1"; }

attach() {
  clang -O2 -g -target bpf -c "$HERE/loss_wire.c" -o "$OBJ" "$@" -I/usr/include/$(uname -m)-linux-gnu
  ip netns exec netW tc qdisc add dev wB clsact 2>/dev/null || true
  ip netns exec netW tc filter del dev wB egress 2>/dev/null || true
  ip netns exec netW tc filter add dev wB egress bpf da obj "$OBJ" sec tc
}

case "$MODE" in
  none)   attach -DLOSS_MODE=0 ;;
  random) attach -DLOSS_MODE=1 -DP_LOSS="$(u32 "$2")u" ;;
  ge)
    L="$2"; BL="$3"
    R=$(python3 -c "print(1.0/float('$BL'))")
    P=$(python3 -c "L=float('$L'); r=1.0/float('$BL'); print(L*r/(1-L) if L<1 else 1.0)")
    attach -DLOSS_MODE=2 -DGE_P="$(u32 "$P")u" -DGE_R="$(u32 "$R")u" -DGE_H1=4294967295u -DGE_K1=0u
    echo "ge p=$P r=$R" ;;
  counters)
    MID=$(ip netns exec netW bpftool map show 2>/dev/null | awk -F: '/loss_state/{print $1}' | tail -1)
    ip netns exec netW bpftool -j map dump id "$MID" | python3 -c "
import json,sys
rows=json.load(sys.stdin)
def v(x):
    if isinstance(x,list): return int.from_bytes(bytes(int(b,16) for b in x),'little')
    if isinstance(x,str): return int(x,16) if x.startswith('0x') else int(x)
    return int(x)
d={v(r['key']): v(r['value']) for r in rows}
print(d.get(0,0), d.get(1,0))" ;;
  off)
    ip netns exec netW tc filter del dev wB egress 2>/dev/null || true ;;
  *) echo "unknown mode" >&2; exit 2 ;;
esac
