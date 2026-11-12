"""Sends raw Ethernet frames from the receiver (B) to the sender (A).

Raw frames bypass iptables and arptables, so this tests the driver-layer
filter. Run on B only, as root, exactly ONCE per capture:

    sudo python3 wired_test/e1_raw.py eno1 <A_MAC>          (sends 50 frames)
    sudo python3 wired_test/e1_raw.py eno1 <A_MAC> 20       (sends 20)

The frames use EtherType 0x88B5 (reserved for local experiments), so on A
they can be captured on their own with:  tcpdump -ni eno1 -e ether proto 0x88b5
"""
import socket
import sys
import time

if len(sys.argv) not in (3, 4):
    sys.exit("usage: sudo python3 e1_raw.py <iface> <A_MAC> [count]")

iface = sys.argv[1]
dst = bytes.fromhex(sys.argv[2].replace(":", "").replace("-", ""))
count = int(sys.argv[3]) if len(sys.argv) == 4 else 50
if len(dst) != 6:
    sys.exit("A_MAC must look like aa:bb:cc:dd:ee:ff")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
src = s.getsockname()[4]
sent = 0
for i in range(count):
    payload = (b"RAIL-RAW-%d" % i).ljust(46, b"\x00")
    try:
        s.send(dst + src + b"\x88\xb5" + payload)
        sent += 1
    except OSError as exc:  # a local egress filter may refuse the frame
        print("frame", i, "refused locally:", exc)
    time.sleep(0.01)
print("raw frames sent: %d of %d  to %s  from %s" % (sent, count, sys.argv[2], src.hex(":")))
