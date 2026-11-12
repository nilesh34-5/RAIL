#!/usr/bin/env bash
# =============================================================================
# EMERGENCY UNLOCK - restore all networking on a RAIL gateway.
#
#     sudo bash unlock.sh
#
# Use this if `railcds.cli lockdown --release` cannot run for any reason (the
# venv is gone, Python is broken, you cannot remember the peer address). It
# touches nothing but the kernel's network configuration and needs no Python.
#
# A total lock sets default-DROP policies, so the policies must be restored
# BEFORE flushing the rules - otherwise the host is left with no networking at
# all. The order below matters.
# =============================================================================
set -uo pipefail

echo "=============================================================="
echo "RAIL emergency unlock"
echo "=============================================================="

echo "[1/6] restoring iptables default policies to ACCEPT ..."
iptables -P INPUT   ACCEPT 2>/dev/null
iptables -P OUTPUT  ACCEPT 2>/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null

echo "[2/6] flushing all iptables rules ..."
iptables -F 2>/dev/null
iptables -X 2>/dev/null
iptables -t nat -F 2>/dev/null
iptables -t mangle -F 2>/dev/null

echo "[3/6] restoring IPv6 ..."
ip6tables -P INPUT   ACCEPT 2>/dev/null
ip6tables -P OUTPUT  ACCEPT 2>/dev/null
ip6tables -P FORWARD ACCEPT 2>/dev/null
ip6tables -F 2>/dev/null
sysctl -w net.ipv6.conf.all.disable_ipv6=0     >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1

echo "[4/6] restoring ARP ..."
if command -v arptables >/dev/null 2>&1; then
    arptables -P INPUT  ACCEPT 2>/dev/null
    arptables -P OUTPUT ACCEPT 2>/dev/null
    arptables -F 2>/dev/null
fi
# drop any statically pinned neighbours so ARP resolves normally again
ip -s neigh flush all >/dev/null 2>&1

echo "[5/6] restoring kernel parameters ..."
sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1

echo "[6/6] detaching any eBPF/XDP filters ..."
for IFACE in $(ls /sys/class/net 2>/dev/null); do
    [ "$IFACE" = "lo" ] && continue
    ip link set dev "$IFACE" xdp off        2>/dev/null
    tc filter del dev "$IFACE" egress       2>/dev/null
    tc qdisc  del dev "$IFACE" clsact       2>/dev/null
done

echo
echo "restarting the network stack ..."
systemctl restart NetworkManager 2>/dev/null \
    || systemctl restart networking 2>/dev/null \
    || echo "  (restart your network service manually if needed)"

sleep 3
echo
echo "=============================================================="
echo "current state:"
echo "--- iptables policies ---"
iptables -S 2>/dev/null | grep '^-P' | sed 's/^/  /'
echo "--- connectivity ---"
if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "  internet: OK"
else
    echo "  internet: still unreachable - check the VM's network adapter"
fi
echo "=============================================================="
