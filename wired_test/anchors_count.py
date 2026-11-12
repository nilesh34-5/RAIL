"""Counts anchors and signed objects on the SENDER (A):

    python3 wired_test/anchors_count.py | tee results_wired/t7_anchors.txt
"""
import json
import sys

ledger = sys.argv[1] if len(sys.argv) > 1 else "data/ledger.jsonl"
audit = sys.argv[2] if len(sys.argv) > 2 else "data/audit_sender.jsonl"

with open(ledger, encoding="utf-8") as fh:
    anchors = sum(1 for line in fh if line.strip())
signed = quarantined = other = 0
with open(audit, encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("event") == "quarantine":
            quarantined += 1
        elif e.get("signature"):
            signed += 1
        else:
            other += 1
ratio = signed / anchors if anchors else 0.0
print("anchors=%d signed=%d quarantined=%d other=%d  signed_per_anchor=%.1f"
      % (anchors, signed, quarantined, other, ratio))
