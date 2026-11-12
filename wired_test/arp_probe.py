"""ARP test for E1 - run on the SENDER (A) as root:

    sudo python3 wired_test/arp_probe.py eno1 192.168.66.89        (4 requests)

Sends ARP "who-has B" requests from A and listens for B's replies. It uses a
raw packet socket, so the lockdown on A does not stop the requests. Under the
lockdown B must not answer. Expected last line: "... replies from B: 0".
"""
import fcntl
import socket
import struct
import sys
import time

if len(sys.argv) not in (3, 4):
    sys.exit("usage: sudo python3 arp_probe.py <iface> <B_IP> [count]")
iface, target = sys.argv[1], sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) == 4 else 4

ETH_P_ARP = 0x0806
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
s.bind((iface, 0))
mac = s.getsockname()[4]
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_ip = fcntl.ioctl(probe.fileno(), 0x8915,  # SIOCGIFADDR
                    struct.pack("256s", iface[:15].encode()))[20:24]
tip = socket.inet_aton(target)

arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + my_ip + b"\x00" * 6 + tip
frame = (b"\xff" * 6 + mac + struct.pack("!H", ETH_P_ARP) + arp).ljust(60, b"\x00")

s.settimeout(0.2)
replies = 0
for i in range(count):
    s.send(frame)
    print("sent ARP who-has %s tell %s  (%d/%d)" % (target, socket.inet_ntoa(my_ip), i + 1, count))
    end = time.time() + 1.0
    while time.time() < end:
        try:
            pkt = s.recv(2048)
        except socket.timeout:
            continue
        # ARP reply (op 2) whose sender IP is B
        if len(pkt) >= 42 and pkt[12:14] == b"\x08\x06" and pkt[20:22] == b"\x00\x02" and pkt[28:32] == tip:
            replies += 1
            print("   reply from %s, MAC %s" % (target, pkt[22:28].hex(":")))
print("ARP requests sent: %d   replies from B: %d" % (count, replies))
