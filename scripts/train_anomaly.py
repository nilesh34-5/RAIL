"""Train the offline byte-distribution anomaly model (IsolationForest).

    python scripts/train_anomaly.py [--dirs D1 D2 ...] [--max-files N]
                                    [--out models/anomaly_isoforest.joblib]

The model is trained ONLY on benign objects (no malware required): it learns the
byte-distribution of ordinary files and flags out-of-distribution payloads
(packed, encrypted, or otherwise unusual).  By default it samples benign files
from the system so the demo is self-contained; point --dirs at a representative
corpus of your real cross-domain traffic for a production model.
"""
import argparse
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np                                     # noqa: E402
from sklearn.ensemble import IsolationForest           # noqa: E402
import joblib                                          # noqa: E402

from railcds.inspection.entropy_anomaly import byte_features  # noqa: E402

DEFAULT_DIRS = [
    r"C:\Windows\System32",
    str(Path(sys.executable).parent / "Lib"),
    str(Path(__file__).resolve().parent.parent),
]
READ_CAP = 1 << 20  # read at most 1 MiB per file


def collect(dirs, max_files):
    paths = []
    for d in dirs:
        base = Path(d)
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file():
                try:
                    if 64 <= p.stat().st_size <= 64 * READ_CAP:
                        paths.append(p)
                except OSError:
                    continue
            if len(paths) >= max_files * 4:
                break
    random.shuffle(paths)
    feats = []
    used = 0
    for p in paths:
        if used >= max_files:
            break
        try:
            data = p.read_bytes()[:READ_CAP]
        except OSError:
            continue
        feats.append(byte_features(data))
        used += 1
    return np.vstack(feats) if feats else np.empty((0, 257))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=DEFAULT_DIRS)
    ap.add_argument("--max-files", type=int, default=1500)
    ap.add_argument("--out", default="models/anomaly_isoforest.joblib")
    args = ap.parse_args()

    print(f"[i] collecting up to {args.max_files} benign files from:")
    for d in args.dirs:
        print(f"    - {d}")
    X = collect(args.dirs, args.max_files)
    if X.shape[0] < 50:
        print(f"[!] only {X.shape[0]} samples found; need >=50", file=sys.stderr)
        return 2
    print(f"[i] training IsolationForest on {X.shape[0]} samples "
          f"({X.shape[1]} features)")
    clf = IsolationForest(n_estimators=200, contamination="auto",
                          random_state=0, n_jobs=-1)
    clf.fit(X)

    out = Path(args.out)
    if not out.is_absolute():
        out = Path(__file__).resolve().parent.parent / out
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out)
    print(f"[+] saved anomaly model -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
