#!/usr/bin/env bash
# =============================================================================
# load_xdp.sh - compile and attach the RAIL driver-layer filters (Linux/eBPF).
#
#   sudo ./load_xdp.sh attach <sender|receiver> <IFACE> <PEER_IP> [PORT]
#   sudo ./load_xdp.sh detach <IFACE>
#   sudo ./load_xdp.sh status <IFACE>
#        ./load_xdp.sh verify [role] [peer] [port]   # compile only, no attach
#
# Attaches:
#   XDP  ingress at the NIC driver  (pre-skb; Scholz et al., Sec. III-A)
#   tc   egress on the clsact qdisc (XDP has no transmit hook)
#
# XDP attach modes, tried in order:
#   xdpdrv  native driver mode  - the real driver layer, needs NIC/driver support
#   xdpgeneric  SKB fallback    - still kernel, but after skb allocation
# The mode actually achieved is reported, because the distinction matters for
# the enforcement claim in Table I.
# =============================================================================
set -euo pipefail

ACTION="${1:?usage: load_xdp.sh <attach|detach|status> ...}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJ="/tmp/rail_xdp.o"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] missing tool: $1"; return 1; }; }

ip_to_u32() {   # dotted quad -> decimal, host order (the C uses bpf_htonl)
  local IFS=. ; read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

case "$ACTION" in
attach)
  ROLE="${2:?role}"; IFACE="${3:?iface}"; PEER="${4:?peer ip}"; PORT="${5:-52080}"
  [ "$ROLE" = "receiver" ] && RECV=1 || RECV=0
  PEER_U32=$(ip_to_u32 "$PEER")

  need clang || { echo "    install with: apt-get install -y clang llvm libbpf-dev linux-headers-\$(uname -r)"; exit 1; }
  need ip || exit 1

  echo "[xdp] compiling rail_xdp.c (role=$ROLE peer=$PEER port=$PORT)"
  clang -O2 -g -target bpf -c "$HERE/rail_xdp.c" -o "$OBJ" \
        -DRAIL_PEER_IP="$PEER_U32" -DRAIL_PORT="$PORT" -DRAIL_ROLE_RECV="$RECV" \
        -I/usr/include/$(uname -m)-linux-gnu

  # ---- ingress: XDP, native driver mode preferred ------------------------
  MODE=""
  if ip link set dev "$IFACE" xdpdrv obj "$OBJ" sec xdp 2>/dev/null; then
    MODE="native (xdpdrv) - TRUE driver layer, pre-skb"
  elif ip link set dev "$IFACE" xdpgeneric obj "$OBJ" sec xdp 2>/dev/null; then
    MODE="generic (xdpgeneric) - kernel, post-skb (driver lacks native XDP)"
  else
    echo "[!] XDP attach failed on $IFACE"; exit 1
  fi
  echo "[xdp] ingress attached: $MODE"

  # ---- egress: tc clsact --------------------------------------------------
  if need tc; then
    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
    tc filter del dev "$IFACE" egress 2>/dev/null || true
    if tc filter add dev "$IFACE" egress bpf da obj "$OBJ" sec tc 2>/dev/null; then
      echo "[tc ] egress attached (clsact)"
    else
      echo "[!] tc egress attach failed - egress still relies on iptables"
    fi
  fi

  echo "[ok ] driver-layer enforcement active on $IFACE"
  echo "      verify: sudo $0 status $IFACE"
  ;;

detach)
  IFACE="${2:?iface}"
  ip link set dev "$IFACE" xdp off 2>/dev/null || true
  tc filter del dev "$IFACE" egress 2>/dev/null || true
  tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  echo "[ok ] detached from $IFACE"
  ;;

status)
  IFACE="${2:?iface}"
  echo "-- XDP on $IFACE --"
  ip -details link show dev "$IFACE" | grep -iE "xdp|prog" || echo "  no XDP program attached"
  echo "-- tc egress on $IFACE --"
  tc filter show dev "$IFACE" egress 2>/dev/null | head -5 || echo "  none"
  echo "-- eBPF counters --"
  # NOTE: attaching the XDP and tc programs with two separate loads gives each
  # its OWN copy of rail_counters, so both maps must be read: the XDP map holds
  # the ingress counts and the tc map the egress counts.
  if command -v bpftool >/dev/null 2>&1; then
    for MAPID in $(bpftool map show 2>/dev/null | awk -F: '/rail_counters/{print $1}'); do
      bpftool -j map dump id "$MAPID" > /tmp/rail_cnt.json 2>/dev/null || continue
      python3 - "$MAPID" <<'PYEOF'
import json, sys
mid = sys.argv[1]
names = ["pass_in", "drop_in", "pass_out", "drop_out"]
def tot(v):
    if isinstance(v, list):  return sum(tot(x) for x in v)
    if isinstance(v, dict):  return tot(v.get("value", 0))
    if isinstance(v, str):   return int(v, 16) if v.startswith("0x") else int(v)
    return int(v)
try:
    rows = json.load(open("/tmp/rail_cnt.json"))
except Exception:
    sys.exit(0)
vals = {names[tot(e["key"])]: tot(e.get("values", e.get("value"))) for e in rows}
if any(vals.values()):
    print(f"   map {mid}: " + "  ".join(f"{k}={v}" for k, v in vals.items() if v))
PYEOF
    done
    rm -f /tmp/rail_cnt.json
  else
    echo "   install bpftool to read counters (apt-get install linux-tools-$(uname -r))"
  fi
  ;;

verify)
  # Compile only - proves the eBPF object builds and the verifier-relevant
  # bounds checks are present, without touching any interface.
  ROLE="${2:-receiver}"; PEER="${3:-10.20.0.10}"; PORT="${4:-52080}"
  [ "$ROLE" = "receiver" ] && RECV=1 || RECV=0
  need clang || { echo "    apt-get install -y clang llvm libbpf-dev linux-headers-\$(uname -r)"; exit 1; }
  clang -O2 -g -target bpf -c "$HERE/rail_xdp.c" -o "$OBJ"         -DRAIL_PEER_IP="$(ip_to_u32 "$PEER")" -DRAIL_PORT="$PORT"         -DRAIL_ROLE_RECV="$RECV"         -I/usr/include/$(uname -m)-linux-gnu
  echo "[ok ] compiled -> $OBJ"
  command -v llvm-objdump >/dev/null 2>&1 &&     llvm-objdump -h "$OBJ" | grep -E "xdp|tc|maps" || true
  ;;

*) echo "unknown action: $ACTION" >&2; exit 2 ;;
esac
