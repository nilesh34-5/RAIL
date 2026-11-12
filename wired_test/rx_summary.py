"""Summarises the receiver's audit log - run on the RECEIVER (B) at the end:

    python3 wired_test/rx_summary.py | tee results_wired/rx_summary.txt

Counts every object the receiver handled, by result. Every delivery must
show verified=True.
"""
import collections
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "data/audit_receiver.jsonl"
c = collections.Counter()
with open(path, encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        e = json.loads(line)
        c[(e.get("event"), e.get("verified"))] += 1
total = sum(c.values())
print("receiver audit log: %s" % path)
print("entries: %d" % total)
for (event, verified), n in sorted(c.items(), key=lambda kv: -kv[1]):
    print("  %-16s verified=%-5s %d" % (event, verified, n))
delivered = sum(n for (ev, _), n in c.items() if ev == "delivered")
ok = c.get(("delivered", True), 0)
print("delivered and verified: %d of %d" % (ok, delivered))
