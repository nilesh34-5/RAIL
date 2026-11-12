"""E5 - inspection accuracy on node A.

Runs RAIL's own InspectionEngine (all detectors exactly as configured) over
  * the benign corpus (build_corpus.py)            -> label 0
  * the project's own synthetic objects
    (RAIL1/scripts/make_test_object.py) and the standard
    EICAR anti-virus test file                      -> label 1 (non-benign)
and writes one JSON line per object with every detector score, the fused
noisy-OR risk computed by RAIL, the band and the per-object inspection time.

    python e5_inspect.py --config CFG --benign /opt/dl/corpus/benign \
                         --positives /opt/dl/corpus/positives --out e5.jsonl
"""
import argparse
import csv
import json
import sys
import time
import warnings
from pathlib import Path

warnings.simplefilter("ignore")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default="/opt/railtb/nodeA")
    ap.add_argument("--config", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--positives", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    sys.path.insert(0, a.node)
    from railcds.config import load_config
    from railcds.inspection.engine import InspectionEngine
    from railcds.models import TransferObject

    cfg = load_config(a.config)
    eng = InspectionEngine(cfg)
    items = []
    with open(Path(a.benign) / "manifest.csv") as f:
        for row in csv.DictReader(f):
            items.append((Path(a.benign) / row["file"], row["class"], 0))
    for p in sorted(Path(a.positives).iterdir()):
        if p.is_file() and not p.name.startswith("."):
            items.append((p, "synthetic", 1))

    done = set()
    outp = Path(a.out)
    if outp.exists():
        for line in outp.read_text().splitlines():
            done.add(json.loads(line)["file"])
    with open(outp, "a") as fo:
        for i, (p, cls, label) in enumerate(items):
            if str(p) in done:
                continue
            data = p.read_bytes()
            obj = TransferObject(name=p.name, data=data)
            t0 = time.perf_counter()
            rep = eng.inspect(obj)
            dt = time.perf_counter() - t0
            fo.write(json.dumps({
                "file": str(p), "class": cls, "label": label, "size": len(data),
                "risk": rep.risk, "band": rep.band, "blocked": rep.blocked,
                "t_inspect_s": dt,
                "det": {r.name: {"s": r.score, "w": r.weight, "ok": r.available,
                                 "detail": r.detail[:120]} for r in rep.results},
            }) + "\n")
            fo.flush()
            if i % 50 == 0:
                print(f"{i}/{len(items)} {cls} {p.name} r={rep.risk:.3f} t={dt:.2f}s", flush=True)


if __name__ == "__main__":
    main()
