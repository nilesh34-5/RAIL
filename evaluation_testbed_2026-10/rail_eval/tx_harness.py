"""Transmit harness for the two-node testbed (drives
railcds.sender.SenderGateway on node A).

Runs inside netns netA. Builds one SenderGateway (obj_id starts at 1) and sends
every object given, over the real UDP socket to 10.20.0.20:52080 across the
wire. Writes one JSON line per object (the gateway's own summary plus the wall
time and byte count) so goodput/overhead can be computed.

    ip netns exec netA /opt/venvA/bin/python tx_harness.py \
        --node /opt/railtb/nodeA --config CFG --out tx.jsonl \
        [--spool DIR | FILE ...] [--repeat N] [--band-steer SPEC]
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
    ap.add_argument("--spool", default=None)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    sys.path.insert(0, a.node)
    from railcds.config import load_config
    from railcds.sender import SenderGateway
    from railcds.protocol_break import ProtocolBreak
    from railcds.models import TransferObject

    cfg = load_config(a.config)
    objs = []
    if a.spool:
        objs += list(ProtocolBreak(spool_dir=Path(a.spool)).iter_spool())
    for f in a.files:
        p = Path(f)
        objs.append(TransferObject(name=p.name, data=p.read_bytes()))
    objs = objs * a.repeat

    # Build the gateway first (this loads the ML models, ~several seconds). Only
    # once it is warm do we signal readiness, so the receiver's idle clock does
    # not run during model loading. Then wait for the controller's "go".
    gw = SenderGateway(cfg)
    warm = Path(a.out + ".warm")
    go = Path(a.out + ".go")
    if go.exists():
        go.unlink()
    warm.write_text(str(time.time()))
    for _ in range(3000):
        if go.exists():
            break
        time.sleep(0.05)
    fo = open(a.out, "w")
    t_start = time.time()
    for obj in objs:
        t0 = time.perf_counter()
        summary = gw.process(obj)
        summary["_wall_s"] = time.perf_counter() - t0
        summary["_t"] = time.time()
        fo.write(json.dumps(summary) + "\n")
        fo.flush()
    gw.close()
    fo.write(json.dumps({"_summary": True, "sent_objects": len(objs),
                         "wall_s": time.time() - t_start}) + "\n")
    fo.close()
    print(f"[tx] sent {len(objs)} objects in {time.time()-t_start:.2f}s")


if __name__ == "__main__":
    main()
