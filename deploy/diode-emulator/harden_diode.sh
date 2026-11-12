#!/usr/bin/env bash
# =============================================================================
# harden_diode.sh - lock a RAIL gateway down to a single one-way UDP flow.
#
#   sudo ./harden_diode.sh sender   [DIODE_IF] [PEER_IP] [PORT] [MGMT_IF]
#   sudo ./harden_diode.sh receiver [DIODE_IF] [PEER_IP] [PORT] [MGMT_IF]
#
# Defaults: DIODE_IF=eth1  PEER_IP=(10.20.0.20|10.20.0.10)  PORT=52080
#           MGMT_IF=eth0   (out-of-band management; NOT part of the diode)
#
# What this enforces, in layers, so that no single failure re-opens the path:
#
#   L2  ARP        receiver never answers ARP; sender uses a static ARP entry
#   L3  IPv4       default DROP; exactly one permitted flow on the diode NIC
#   L3  IPv6       disabled on the diode NIC (NDP/RA are inherently two-way)
#   L4  UDP only   one destination port; no TCP, no ICMP
#   ICMP           suppressed, so port-unreachable cannot become a back channel
#   routing        IP forwarding off, so neither gateway relays for anything
#
# The management interface is left open ON PURPOSE so you keep `vagrant ssh`.
# In a real deployment that interface belongs on a separate physical network,
# never on the diode segment.
# =============================================================================
set -euo pipefail

ROLE="${1:?usage: harden_diode.sh <sender|receiver> [DIODE_IF] [PEER_IP] [PORT] [MGMT_IF]}"
DIODE_IF="${2:-eth1}"
PORT="${4:-52080}"
MGMT_IF="${5:-eth0}"

case "$ROLE" in
  sender)   PEER_IP="${3:-10.20.0.20}" ;;
  receiver) PEER_IP="${3:-10.20.0.10}" ;;
  *) echo "role must be 'sender' or 'receiver'" >&2; exit 2 ;;
esac

echo "[harden] role=$ROLE diode_if=$DIODE_IF peer=$PEER_IP port=$PORT mgmt_if=$MGMT_IF"

# --- kernel-level hygiene ---------------------------------------------------
sysctl -w net.ipv4.ip_forward=0                        >/dev/null
sysctl -w net.ipv4.conf.all.accept_redirects=0         >/dev/null
sysctl -w net.ipv4.conf.all.send_redirects=0           >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=1                >/dev/null
sysctl -w net.ipv4.icmp_echo_ignore_all=1              >/dev/null
# IPv6 neighbour discovery and router advertisement are two-way by design:
# there is no way to run IPv6 on a strictly unidirectional segment.
sysctl -w "net.ipv6.conf.${DIODE_IF}.disable_ipv6=1"   >/dev/null || true

# --- IPv4 firewall ----------------------------------------------------------
iptables -F
iptables -X
iptables -P INPUT   DROP
iptables -P OUTPUT  DROP
iptables -P FORWARD DROP

# loopback stays usable (local IPC, not a cross-domain path)
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# out-of-band management plane (SSH, apt). Separate NIC in production.
iptables -A INPUT  -i "$MGMT_IF" -j ACCEPT
iptables -A OUTPUT -o "$MGMT_IF" -j ACCEPT

if [ "$ROLE" = "sender" ]; then
  # Exactly one thing may leave on the diode NIC: UDP to the receiver's port.
  iptables -A OUTPUT -o "$DIODE_IF" -p udp -d "$PEER_IP" --dport "$PORT" -j ACCEPT
  # Nothing whatsoever may be accepted from the diode NIC.
  iptables -A INPUT  -i "$DIODE_IF" -j DROP
  echo "[harden] sender: OUT udp/$PORT -> $PEER_IP only; ALL ingress on $DIODE_IF dropped"
else
  # Exactly one thing may be accepted: UDP from the sender to our port.
  iptables -A INPUT  -i "$DIODE_IF" -p udp -s "$PEER_IP" --dport "$PORT" -j ACCEPT
  # Nothing whatsoever may leave on the diode NIC - no ACKs, no ICMP, no RST.
  iptables -A OUTPUT -o "$DIODE_IF" -j DROP
  echo "[harden] receiver: IN udp/$PORT from $PEER_IP only; ALL egress on $DIODE_IF dropped"
fi

# --- IPv6 firewall (belt and braces if the NIC could not be disabled) -------
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -F || true
  ip6tables -P INPUT   DROP || true
  ip6tables -P OUTPUT  DROP || true
  ip6tables -P FORWARD DROP || true
  ip6tables -A INPUT  -i lo -j ACCEPT || true
  ip6tables -A OUTPUT -o lo -j ACCEPT || true
  ip6tables -A INPUT  -i "$MGMT_IF" -j ACCEPT || true
  ip6tables -A OUTPUT -o "$MGMT_IF" -j ACCEPT || true
fi

# --- Layer 2: ARP -----------------------------------------------------------
# iptables does not see ARP. Without this step the receiver still answers ARP
# requests, which is a genuine frame travelling B -> A: a reverse channel.
if ! command -v arptables >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y arptables >/dev/null 2>&1 || true
fi

if [ "$ROLE" = "receiver" ]; then
  if command -v arptables >/dev/null 2>&1; then
    arptables -F || true
    # Scope the ARP block to the DIODE interface only. A global
    # 'arptables -P OUTPUT DROP' also silences ARP on the management NIC, and
    # the gateway becomes unreachable as soon as its ARP cache expires.
    arptables -P OUTPUT ACCEPT || true
    arptables -A OUTPUT -o "$DIODE_IF" -j DROP || true
    echo "[harden] receiver: ARP egress dropped on $DIODE_IF only"
    echo "[harden]           (management NIC $MGMT_IF keeps ARP, or you lose SSH)"
  else
    echo "[harden] WARNING: arptables unavailable - receiver may still answer ARP"
  fi
else
  # The sender cannot rely on ARP resolution any more (B will never reply), so
  # pin the peer's MAC statically. Supply it via PEER_MAC, or discover it once
  # BEFORE hardening the receiver.
  if [ -n "${PEER_MAC:-}" ]; then
    ip neigh replace "$PEER_IP" lladdr "$PEER_MAC" dev "$DIODE_IF" nud permanent
    echo "[harden] sender: static ARP $PEER_IP -> $PEER_MAC on $DIODE_IF"
  else
    CUR=$(ip neigh show "$PEER_IP" dev "$DIODE_IF" 2>/dev/null | awk '{print $3}' | head -1)
    if [ -n "$CUR" ]; then
      ip neigh replace "$PEER_IP" lladdr "$CUR" dev "$DIODE_IF" nud permanent
      echo "[harden] sender: pinned learned MAC $CUR for $PEER_IP"
    else
      echo "[harden] WARNING: no ARP entry for $PEER_IP."
      echo "         Ping B once BEFORE hardening it, or re-run with:"
      echo "           sudo PEER_MAC=aa:bb:cc:dd:ee:ff $0 $ROLE"
    fi
  fi
fi

# --- persist across reboot --------------------------------------------------
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
elif [ -d /etc/iptables ]; then
  iptables-save  > /etc/iptables/rules.v4 || true
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
fi

echo "[harden] done. Verify with: sudo ./verify_diode.sh $ROLE $DIODE_IF $PEER_IP"
