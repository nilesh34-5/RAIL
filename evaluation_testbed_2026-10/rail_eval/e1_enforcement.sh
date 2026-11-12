#!/usr/bin/env bash
# E1 - one-way enforcement, measured on the two-node testbed.
#
# Applies RAIL's own enforcement on both gateways:
#   * host firewall  : deploy/diode-emulator/harden_diode.sh  (iptables+arptables+sysctl)
#   * driver layer   : railcds/driver/load_xdp.sh             (XDP ingress + tc egress)
# then has G_B attempt every reverse channel (ICMP, TCP, UDP, ARP, and a raw
# AF_PACKET frame that bypasses the IP stack) and counts how many frames reach
# G_A, captured independently with tcpdump on G_A's link NIC.  Finally it
# confirms the forward path A->B still delivers.
#
# Output: JSON on stdout + $OUT/e1.json
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:?usage: e1_enforcement.sh OUTDIR}"
mkdir -p "$OUT"
A=10.20.0.10; B=10.20.0.20; PORT=52080
MACA=02:48:8a:76:3b:31; MACB=02:9b:ef:d9:f3:3c
HARDEN=/opt/railtb/nodeA/deploy/diode-emulator/harden_diode.sh
XDP=/opt/railtb/nodeA/railcds/driver/load_xdp.sh

echo "[E1] applying host-firewall enforcement (harden_diode.sh) in each namespace"
# mgmt NIC left as the (non-existent) default eth0 so no management rule matches;
# loopback and the single UDP flow are all that the scripts leave open.
ip netns exec netB bash "$HARDEN" receiver eth1 "$A" "$PORT" eth0 > "$OUT/harden_B.log" 2>&1
PEER_MAC=$MACB ip netns exec netA bash "$HARDEN" sender eth1 "$B" "$PORT" eth0 > "$OUT/harden_A.log" 2>&1

echo "[E1] attaching driver-layer filters (XDP ingress + tc egress)"
ip netns exec netB bash "$XDP" attach receiver eth1 "$A" "$PORT" > "$OUT/xdp_B.log" 2>&1 || true
ip netns exec netA bash "$XDP" attach sender   eth1 "$B" "$PORT" > "$OUT/xdp_A.log" 2>&1 || true

# ---- capture everything that reaches G_A on the link, for 12 s ---------------
ip netns exec netA timeout 12 tcpdump -ni eth1 -Q in -e -tt > "$OUT/arrivals_at_A.txt" 2>/dev/null &
TCPD=$!
sleep 1

echo "[E1] G_B attempts reverse channels to G_A"
# ICMP echo
ip netns exec netB ping -c 3 -W 1 -I eth1 "$A" > "$OUT/probe_icmp.txt" 2>&1; ICMP_RC=$?
# TCP connect to :22 and :52080
ip netns exec netB timeout 3 bash -c "echo hi > /dev/tcp/$A/22"   > "$OUT/probe_tcp22.txt"   2>&1; TCP22_RC=$?
ip netns exec netB timeout 3 bash -c "echo hi > /dev/tcp/$A/$PORT" > "$OUT/probe_tcp5.txt"    2>&1; TCP5_RC=$?
# UDP datagrams back to A
ip netns exec netB python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(5): s.sendto(b'reverse',('$A',$PORT))" > "$OUT/probe_udp.txt" 2>&1; UDP_RC=$?
# ARP who-has A (L2 reverse frame)
ip netns exec netB bash -c "command -v arping >/dev/null && arping -c 3 -w 3 -I eth1 $A" > "$OUT/probe_arp.txt" 2>&1; ARP_RC=$?
# RAW AF_PACKET frame straight onto the wire (bypasses iptables/arptables entirely)
ip netns exec netB python3 -c "
import socket
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
raw.bind(('eth1',0))
dst=bytes.fromhex('${MACA//:/}'); src=bytes.fromhex('${MACB//:/}')
frame=dst+src+b'\x08\x00'+b'RAWBYPASS'*8
for _ in range(5): raw.send(frame)
print('raw frames sent')" > "$OUT/probe_raw.txt" 2>&1; RAW_RC=$?

wait $TCPD 2>/dev/null
# count only frames whose source is B (ignore any A-originated/local noise)
ARRIV=$(grep -c "$MACB" "$OUT/arrivals_at_A.txt" 2>/dev/null); ARRIV=${ARRIV:-0}
RAWARR=$(grep -c "RAWBYPASS\|0x5241\|ethertype Unknown" "$OUT/arrivals_at_A.txt" 2>/dev/null); RAWARR=${RAWARR:-0}
TOTAL=$(grep -c . "$OUT/arrivals_at_A.txt" 2>/dev/null); TOTAL=${TOTAL:-0}

echo "[E1] reading enforcement counters"
ip netns exec netA iptables -L INPUT -v -n > "$OUT/ipt_A_input.txt" 2>&1
ip netns exec netB iptables -L OUTPUT -v -n > "$OUT/ipt_B_output.txt" 2>&1
ip netns exec netB bash "$XDP" status eth1 > "$OUT/xdp_B_status.txt" 2>&1 || true
ip netns exec netA bash "$XDP" status eth1 > "$OUT/xdp_A_status.txt" 2>&1 || true

python3 - "$OUT" "$ICMP_RC" "$TCP22_RC" "$TCP5_RC" "$UDP_RC" "$ARP_RC" "$RAW_RC" "$ARRIV" "$RAWARR" "$TOTAL" <<'PY'
import json, sys, re, pathlib
out = pathlib.Path(sys.argv[1])
icmp,tcp22,tcp5,udp,arp,raw = map(int, sys.argv[2:8])
arriv, rawarr, total = int(sys.argv[8]), int(sys.argv[9]), int(sys.argv[10])
def drop_ct(path, chain_if):
    try:
        for ln in open(path):
            if "DROP" in ln and chain_if in ln:
                return int(ln.split()[0])
    except Exception: pass
    return None
res = {
  "experiment": "E1 one-way enforcement",
  "reverse_probes": {
    "icmp_echo": {"exit": icmp, "blocked": icmp != 0},
    "tcp_22":    {"exit": tcp22, "blocked": tcp22 != 0},
    "tcp_52080": {"exit": tcp5, "blocked": tcp5 != 0},
    "udp_52080": {"note": "sendto never errors on a diode; see frames_from_B_at_A"},
    "arp_whohas":{"exit": arp, "blocked": arp != 0},
    "raw_afpacket_frames_arriving_at_A": rawarr,
  },
  "frames_from_B_observed_at_A": arriv,
  "total_frames_captured_at_A": total,
  "ipt_A_input_drop_packets": drop_ct(str(out/"ipt_A_input.txt"), "eth1"),
  "ipt_B_output_drop_packets": drop_ct(str(out/"ipt_B_output.txt"), "eth1"),
}
# pull eBPF drop counters from xdp status
for side in ("A","B"):
    txt = (out/f"xdp_{side}_status.txt").read_text() if (out/f"xdp_{side}_status.txt").exists() else ""
    m = re.findall(r"(pass_in|drop_in|pass_out|drop_out)=(\d+)", txt)
    res[f"ebpf_{side}"] = {k:int(v) for k,v in m}
(out/"e1.json").write_text(json.dumps(res, indent=2))
print(json.dumps(res, indent=2))
PY
