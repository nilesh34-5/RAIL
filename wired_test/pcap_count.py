"""Counts the packets in a tcpdump .pcap file. Prints one number.

    python3 wired_test/pcap_count.py results_wired/e1_raw_off.pcap

Use this instead of "tcpdump -r FILE | wc -l". For raw frames tcpdump also
prints hex-dump lines, so a line count overstates the number of packets.
"""
import struct
import sys

if len(sys.argv) != 2:
    sys.exit("usage: python3 pcap_count.py FILE.pcap")
with open(sys.argv[1], "rb") as fh:
    data = fh.read()
if len(data) < 24:
    print(0)
    sys.exit(0)
magic = data[:4]
if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    end = "<"
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    end = ">"
else:
    sys.exit("not a classic pcap file")
off, n = 24, 0
while off + 16 <= len(data):
    incl = struct.unpack(end + "I", data[off + 8:off + 12])[0]
    off += 16 + incl
    n += 1
print(n)
