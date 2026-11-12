"""Receiver harness for the two-node testbed (drives
railcds.receiver.ReceiverGateway on node B).

Runs inside netns netB. Binds the real UDP socket on 10.20.0.20:52080, serves
until idle, and writes one JSON line per delivered/rejected object (the exact
dict the gateway's on_result callback produces) plus a final summary line.

    ip netns exec netB /opt/venvB/bin/python rx_harness.py \
        --node /opt/railtb/nodeB --config CFG --out rx.jsonl \
        --idle 8 --expect N
"""
import argparse
import json
import sys
import time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--outdir", default=None, help="delivery directory (S6)")
    ap.add_argument("--idle", type=float, default=8.0)
    ap.add_argument("--expect", type=int, default=0)
    a = ap.parse_args()
    sys.path.insert(0, a.node)
    from railcds.config import load_config
    from railcds.receiver import ReceiverGateway

    cfg = load_config(a.config)
    results = []
    fo = open(a.out, "w")

    def on_result(r):
        r["_t"] = time.time()
        results.append(r)
        fo.write(json.dumps(r) + "\n")
        fo.flush()

    out = Path(a.outdir) if a.outdir else None
    gw = ReceiverGateway(cfg, out_dir=out, on_result=on_result)
    # ready marker: the harness controller waits for this before it starts tx
    Path(a.out + ".ready").write_text(str(time.time()))
    gw.serve(idle_timeout=a.idle)
    gw.close()
    delivered = sum(1 for r in results if r.get("status") == "DELIVERED")
    summary = {"_summary": True, "received_objects": len(results),
               "delivered": delivered,
               "rejected": len(results) - delivered}
    fo.write(json.dumps(summary) + "\n")
    fo.close()
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
