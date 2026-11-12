#!/usr/bin/env bash
# =============================================================================
# verify_diode.sh - evidence that the one-way property actually holds.
#
#   sudo ./verify_diode.sh <sender|receiver> [DIODE_IF] [PEER_IP] [PORT]
#
# Run the RECEIVER check first (it tries to talk back and must fail), then the
# SENDER check (it captures the diode NIC and must see zero inbound frames).
# =============================================================================
set -uo pipefail

ROLE="${1:?usage: verify_diode.sh <sender|receiver> [DIODE_IF] [PEER_IP] [PORT]}"
DIODE_IF="${2:-eth1}"
PORT="${4:-52080}"
case "$ROLE" in
  sender)   PEER_IP="${3:-10.20.0.20}" ;;
  receiver) PEER_IP="${3:-10.20.0.10}" ;;
  *) echo "role must be 'sender' or 'receiver'" >&2; exit 2 ;;
esac

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; RC=1; }
RC=0

echo "==============================================================="
echo "RAIL diode verification - role=$ROLE if=$DIODE_IF peer=$PEER_IP"
echo "==============================================================="

echo
echo "-- active filter policy --"
iptables -S | grep -E '^-P' | sed 's/^/  /'

if [ "$ROLE" = "receiver" ]; then
  echo
  echo "-- the receiver must not be able to reach Network A at all --"

  ping -c 2 -W 2 -I "$DIODE_IF" "$PEER_IP" >/dev/null 2>&1 \
    && fail "ICMP echo to $PEER_IP SUCCEEDED (reverse path open)" \
    || pass "ICMP echo to $PEER_IP blocked"

  timeout 4 bash -c "cat < /dev/tcp/$PEER_IP/22" >/dev/null 2>&1 \
    && fail "TCP/22 to $PEER_IP SUCCEEDED (reverse path open)" \
    || pass "TCP/22 to $PEER_IP blocked"

  echo "test" 2>/dev/null | timeout 3 nc -u -w2 "$PEER_IP" "$PORT" >/dev/null 2>&1
  OUT=$(iptables -L OUTPUT -v -n | awk -v i="$DIODE_IF" '$0 ~ i && /DROP/ {print $1}' | head -1)
  [ -n "${OUT:-}" ] && [ "${OUT:-0}" -gt 0 ] \
    && pass "egress DROP counter on $DIODE_IF is non-zero ($OUT packets stopped)" \
    || echo "  [INFO] egress DROP counter: ${OUT:-0}"

  if command -v arptables >/dev/null 2>&1; then
    arptables -L 2>/dev/null | grep -qi 'policy DROP' \
      && pass "ARP egress policy is DROP (no L2 replies to A)" \
      || fail "ARP egress is NOT dropped - B still answers ARP"
  else
    echo "  [WARN] arptables not installed; ARP replies may still leave B"
  fi

  V6=$(cat "/proc/sys/net/ipv6/conf/$DIODE_IF/disable_ipv6" 2>/dev/null || echo 0)
  [ "$V6" = "1" ] && pass "IPv6 disabled on $DIODE_IF" \
                  || fail "IPv6 still enabled on $DIODE_IF (NDP is two-way)"
else
  echo
  echo "-- the sender must observe ZERO inbound frames on the diode NIC --"
  echo "  capturing 15s on $DIODE_IF (run a transfer now from this VM)..."
  CAP=$(timeout 15 tcpdump -ni "$DIODE_IF" -Q in -c 5 2>/dev/null | wc -l)
  [ "$CAP" -eq 0 ] \
    && pass "no inbound packets captured on $DIODE_IF" \
    || fail "$CAP inbound packet(s) seen on $DIODE_IF - inspect with: tcpdump -ni $DIODE_IF -Q in"

  IN=$(iptables -L INPUT -v -n | awk -v i="$DIODE_IF" '$0 ~ i && /DROP/ {print $1}' | head -1)
  echo "  [INFO] ingress DROP counter on $DIODE_IF: ${IN:-0}"

  ip neigh show "$PEER_IP" 2>/dev/null | grep -q PERMANENT \
    && pass "static ARP entry pinned for $PEER_IP" \
    || echo "  [WARN] no permanent ARP entry; delivery will stop once B stops answering ARP"
fi

echo
echo "-- forwarding must be off on both gateways --"
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "0" ] \
  && pass "net.ipv4.ip_forward = 0" || fail "IP forwarding is ENABLED"

echo
echo "==============================================================="
[ "$RC" -eq 0 ] && echo "RESULT: one-way properties hold" \
                || echo "RESULT: ONE OR MORE CHECKS FAILED - see above"
echo "==============================================================="
exit "$RC"
