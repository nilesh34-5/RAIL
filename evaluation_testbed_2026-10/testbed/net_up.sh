#!/usr/bin/env bash
# =============================================================================
# Two-node RAIL testbed network (emulates the two-VM lab of deploy/vagrant).
#
#   netA (G_A, sender)  eth1 10.20.0.10 --- wA [ netW: br0 = the wire ] wB --- eth1 10.20.0.20 (G_B, receiver)  netB
#
# netA and netB are the two gateways (separate network stacks, firewalls, ARP
# tables, sysctls and eBPF attachments).  netW holds a plain L2 bridge that
# plays the physical link: it has no IP address, forwards every frame, and is
# where the experiments (a) tap the wire to count frames in each direction and
# (b) attach the loss emulator (loss_wire.c) on the port facing G_B.
# Node working copies under /opt/railtb are not touched by this script.
# =============================================================================
set -euo pipefail
for ns in netA netB netW; do ip netns del $ns 2>/dev/null || rm -f /run/netns/$ns; done
ip netns add netA; ip netns add netB; ip netns add netW

ip link add eth1 netns netA type veth peer name wA netns netW
ip link add eth1 netns netB type veth peer name wB netns netW
ip -n netA link set eth1 address 02:48:8a:76:3b:31
ip -n netB link set eth1 address 02:9b:ef:d9:f3:3c
ip -n netA addr add 10.20.0.10/24 dev eth1
ip -n netB addr add 10.20.0.20/24 dev eth1

ip -n netW link add br0 type bridge stp_state 0 forward_delay 0
ip netns exec netW sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true  # kernel may lack IPv6
for p in wA wB; do ip -n netW link set $p master br0; ip -n netW link set $p up; done
ip -n netW link set br0 up
ip -n netW link set lo up

for ns in netA netB; do
  ip -n $ns link set lo up
  ip -n $ns link set eth1 up
done
for ns in netA netB netW; do
  for i in $(ip -n $ns -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v '^lo$'); do
    ip netns exec $ns ethtool -K "$i" tso off gso off gro off tx off >/dev/null 2>&1 || true
  done
done
sleep 2
ip netns exec netA ping -c 1 -W 2 10.20.0.20 >/dev/null && echo "[net] netA -> netB reachable through the wire"
echo "[net] A eth1 $(ip -n netA -br link show eth1 | awk '{print $3}')  B eth1 $(ip -n netB -br link show eth1 | awk '{print $3}')"
