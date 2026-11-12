"""Benchmark the ML detectors against each other on the same objects.

    python scripts/benchmark_models.py [--dirs D1 D2] [--n 12]

Runs every *available* ML/DL detector over a common object set and reports each
model's score and wall-clock latency.  Produces the comparison table used in the
evaluation chapter: gradient-boosted trees (EMBER2024) against the two
deep raw-byte CNNs (MalConv, MalConvGCT), plus the unsupervised anomaly model.

Benign PE samples are drawn from the local system (known-good Windows/Python
binaries); harmless synthetic objects come from data/spool.  No real malware is
used or required.
"""
import argparse
import os
import sys
import time
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
warnings.simplefilter("ignore")

from railcds.config import load_config                  # noqa: E402
from railcds.inspection.engine import InspectionEngine  # noqa: E402
from railcds.models import TransferObject               # noqa: E402

ML_DETECTORS = ("ember2024_ml", "malconv_ml", "malconvgct_ml",
                "ember_ml", "entropy_anomaly")
DEFAULT_PE_DIRS = [r"C:\Windows\System32", str(Path(sys.executable).parent)]


def collect_pe(dirs, n):
    out = []
    for d in dirs:
        base = Path(d)
        if not base.exists():
            continue
        for p in sorted(base.glob("*.exe")):
            try:
                if 16_000 <= p.stat().st_size <= 8_000_000:
                    out.append(p)
            except OSError:
                continue
            if len(out) >= n:
                return out
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=DEFAULT_PE_DIRS)
    ap.add_argument("--n", type=int, default=6, help="benign PE samples")
    args = ap.parse_args()

    engine = InspectionEngine(load_config())
    active = [d for d in engine.detectors if d.name in ML_DETECTORS and d.available]
    if not active:
        print("[!] no ML detectors available - run scripts/download_models.py")
        return 2

    objs = []
    for p in collect_pe(args.dirs, args.n):
        objs.append((TransferObject(name=p.name, data=p.read_bytes()), "benign PE"))
    spool = Path("data/spool")
    if spool.exists():
        for p in sorted(spool.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                objs.append((TransferObject(name=p.name, data=p.read_bytes()),
                             "synthetic"))
    if not objs:
        print("[!] no objects found")
        return 2

    names = [d.name for d in active]
    print("=" * (34 + 16 * len(names)))
    print("ML detector comparison - score per model (higher = more suspicious)")
    print("=" * (34 + 16 * len(names)))
    hdr = f"{'object':22} {'class':11}" + "".join(f"{n[:14]:>15}" for n in names)
    print(hdr); print("-" * len(hdr))

    totals = {n: [0.0, 0.0] for n in names}    # [score_sum, seconds]
    for obj, cls in objs:
        row = f"{obj.name[:21]:22} {cls:11}"
        for d in active:
            t0 = time.perf_counter()
            res = d.evaluate(obj)
            dt = time.perf_counter() - t0
            totals[d.name][0] += res.score
            totals[d.name][1] += dt
            row += f"{res.score:15.3f}"
        print(row)

    print("-" * len(hdr))
    n = len(objs)
    print(f"{'MEAN score':22} {'':11}" +
          "".join(f"{totals[x][0]/n:15.3f}" for x in names))
    print(f"{'MEAN latency (ms)':22} {'':11}" +
          "".join(f"{1000*totals[x][1]/n:15.1f}" for x in names))
    print("=" * len(hdr))
    print(f"\n{n} objects | detectors: {', '.join(names)}")
    print("Benign PEs should score LOW; a model scoring them high is over-flagging.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
