#!/usr/bin/env bash
# =============================================================================
# RAIL two-node testbed (emulates the two-VM lab of deploy/vagrant).
#
#   G_A  "netA"  sender gateway    10.20.0.10/24 on eth1   (Network A side)
#   G_B  "netB"  receiver gateway  10.20.0.20/24 on eth1   (Network B side)
#
# Each node is a separate Linux network namespace with its own interfaces,
# routing table, ARP table, sysctls, iptables/arptables rule sets and eBPF
# attachments, joined by one virtual Ethernet (veth) pair that plays the role of
# the diode link.  Each node also has its own working copy of RAIL1 and its own
# Python virtual environment: the receiver gets ONLY the receiver package and the
# core libraries (no inspection code, no models, no private key), exactly as in
# dist/RECEIVER.
# =============================================================================
set -euo pipefail

SRC="${1:?usage: setup_testbed.sh /path/to/RAIL1}"   # RAIL1 source tree
ROOT=/opt/railtb
A=$ROOT/nodeA
B=$ROOT/nodeB

echo "[tb] building node working copies from $SRC"
rm -rf "$ROOT"; mkdir -p "$A" "$B"

# ---- node A: full sender package (no locally trained model) ------------------
rsync -a --exclude 'dist' --exclude '__pycache__' --exclude '.pytest_cache' \
      --exclude 'deploy/vagrant/.vagrant' --exclude 'data/received' \
      --exclude 'models' --exclude 'data/keys' \
      "$SRC/" "$A/"
mkdir -p "$A/models" "$A/data/keys" "$A/data/spool"

# ---- node B: receiver package only (mirrors dist/RECEIVER) -------------------
mkdir -p "$B/railcds" "$B/config" "$B/data/keys" "$B/data/received"
rsync -a --exclude '__pycache__' --exclude 'inspection' "$SRC/railcds/" "$B/railcds/"
cp "$SRC/config/rail.yaml" "$B/config/rail.yaml"
cp -r "$SRC/deploy" "$B/deploy"

# ---- network namespaces + veth "diode link" ---------------------------------
for ns in netA netB; do ip netns del $ns 2>/dev/null || true; done
ip netns add netA
ip netns add netB
ip link add vethA type veth peer name vethB
ip link set vethA netns netA
ip link set vethB netns netB
ip -n netA link set vethA name eth1
ip -n netB link set vethB name eth1
ip -n netA addr add 10.20.0.10/24 dev eth1
ip -n netB addr add 10.20.0.20/24 dev eth1
for ns in netA netB; do
  ip -n $ns link set lo up
  ip -n $ns link set eth1 up
done
# stop the veth from doing segmentation tricks so frame counts are exact
for ns in netA netB; do
  ip netns exec $ns ethtool -K eth1 tso off gso off gro off >/dev/null 2>&1 || true
done
sleep 1
ip netns exec netA ping -c 2 -W 1 10.20.0.20 >/dev/null && echo "[tb] link up: netA -> netB reachable"
ip -n netA neigh show
echo "[tb] node A MAC: $(ip -n netA -br link show eth1 | awk '{print $3}')"
echo "[tb] node B MAC: $(ip -n netB -br link show eth1 | awk '{print $3}')"
echo "[tb] done"
