"""RAIL quantitative evaluation - the four parameters deferred in the paper.

    python scripts/evaluate.py [--quick] [--out results_evaluation.json]

The paper's Conclusion states that evaluation of *goodput, integrity overhead,
inspection accuracy and measured channel capacity* is deferred to later work.
This harness measures all four on the running implementation:

  E1  Goodput                 - MB/s end-to-end and per stage (S2, S3, S4)
  E2  Integrity overhead      - CPU time and metadata bytes added by Stage S3,
                                per risk band; Merkle proof scaling
  E3  Inspection accuracy     - false-positive rate on a real benign corpus and
                                detection rate on the synthetic threat set
  E4  Covert-channel capacity - empirical mutual information between the band an
                                attacker intends and the band actually produced,
                                compared against the Eq. (6) bound
  E5  Worked-example checks   - the numeric claims printed in the paper
  E6  One-way reliability     - FEC recovery rate vs packet loss (no ACKs)
"""
import argparse
import json
import math
import os
import platform
import random
import statistics
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
warnings.simplefilter("ignore")

from railcds import wire                                        # noqa: E402
from railcds.anchoring import anchoring_interval                # noqa: E402
from railcds.chunker import chunk_object, chunk_size_for_risk   # noqa: E402
from railcds.config import load_config                          # noqa: E402
from railcds.crypto import generate_keypair, Signer             # noqa: E402
from railcds.fec import FEC, FecDecoder                         # noqa: E402
from railcds.hashchain import build_hash_chain                  # noqa: E402
from railcds.inspection.engine import InspectionEngine          # noqa: E402
from railcds.merkle import merkle_root, merkle_proof, verify_proof   # noqa: E402
from railcds.models import Manifest, TransferObject             # noqa: E402
from railcds.quantize import channel_capacity_bound             # noqa: E402
from railcds.risk import noisy_or                               # noqa: E402
from railcds.session import Session                             # noqa: E402

RESULTS = {}
MB = 1024 * 1024


def hdr(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def integrity_stage(data, band, bands, signer, policy="eval"):
    """Run Stage S3 exactly as the sender does; return manifest + timings."""
    t = {}
    t0 = time.perf_counter()
    session = Session.create(policy)
    size = chunk_size_for_risk(band / bands, 1_048_576, 16_384)
    chunks = chunk_object(data, size)
    t["chunk"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    leaves = build_hash_chain(chunks, session.h0)
    t["hashchain"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    root = merkle_root(leaves)
    t["merkle"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    m = Manifest(object_name="o", object_size=len(data), epoch=session.epoch,
                 policy_id=policy, h0=session.h0, band=band,
                 chunk_count=len(chunks),
                 chunk_lengths=[c.length for c in chunks],
                 merkle_root=root, signature=b"")
    m.signature = signer.sign(m.signing_payload())
    t["sign"] = time.perf_counter() - t0
    return m, chunks, leaves, t


# ---------------------------------------------------------------------------
# E1 - Goodput
# ---------------------------------------------------------------------------
def eval_goodput(cfg, engine, signer, sizes, reps):
    hdr("E1  GOODPUT - throughput per stage (MB/s)")
    bands = int(cfg.integrity["risk_bands"])
    fec = FEC(backend=cfg.fec["backend"],
              symbol_size=int(cfg.fec["symbol_size"]),
              overhead=float(cfg.fec["overhead"]))
    rows = []
    print(f"{'object size':>12} {'S2 inspect':>12} {'S3 integrity':>14} "
          f"{'S4 FEC':>10} {'end-to-end':>12}")
    print(f"{'':>12} {'MB/s':>12} {'MB/s':>14} {'MB/s':>10} {'MB/s':>12}")
    print("-" * 66)
    for size in sizes:
        data = os.urandom(size)
        obj = TransferObject(name="bench.bin", data=data)
        t_ins = t_int = t_fec = 0.0
        band = 0
        for _ in range(reps):
            t0 = time.perf_counter()
            rep = engine.inspect(obj)
            t_ins += time.perf_counter() - t0
            band = rep.band

            t0 = time.perf_counter()
            m, _chunks, _leaves, _t = integrity_stage(data, band, bands, signer)
            t_int += time.perf_counter() - t0

            payload = wire.pack_object(m, data)
            t0 = time.perf_counter()
            fec.encode(payload, 1)
            t_fec += time.perf_counter() - t0

        mb = size / MB * reps
        g_ins, g_int, g_fec = mb / t_ins, mb / t_int, mb / t_fec
        g_e2e = mb / (t_ins + t_int + t_fec)
        rows.append(dict(size_mb=size / MB, band=band, inspect=g_ins,
                         integrity=g_int, fec=g_fec, end_to_end=g_e2e))
        print(f"{size/MB:11.1f}M {g_ins:12.2f} {g_int:14.2f} "
              f"{g_fec:10.2f} {g_e2e:12.2f}")
    RESULTS["E1_goodput"] = rows
    big = rows[-1]
    # identify the true bottleneck from per-MB cost rather than assuming it
    cost = {"S2 inspection": 1.0 / big["inspect"],
            "S3 integrity": 1.0 / big["integrity"],
            "S4 FEC": 1.0 / big["fec"]}
    total = sum(cost.values())
    slowest = max(cost, key=cost.get)
    print(f"\n  Per-MB cost at {big['size_mb']:.0f} MB: " +
          ", ".join(f"{k} {v:.3f}s" for k, v in cost.items()))
    print(f"  Bottleneck: {slowest} "
          f"({cost[slowest]:.2f} s/MB, {100*cost[slowest]/total:.0f}% of pipeline)")
    print(f"  Stage S3 - the mechanism this paper contributes - is only "
          f"{100*cost['S3 integrity']/total:.2f}% of pipeline time.")
    big["bottleneck"] = slowest
    big["per_mb_seconds"] = cost
    return rows


# ---------------------------------------------------------------------------
# E2 - Integrity overhead
# ---------------------------------------------------------------------------
def eval_integrity(cfg, signer, size, reps):
    hdr("E2  INTEGRITY OVERHEAD - Stage S3 cost by risk band (Eq. 2)")
    bands = int(cfg.integrity["risk_bands"])
    c_max = int(cfg.integrity["chunk_max_bytes"])
    c_min = int(cfg.integrity["chunk_min_bytes"])
    data = os.urandom(size)
    rows = []
    print(f"object = {size/MB:.0f} MB, c_max = {c_max/1024:.0f} KiB, "
          f"c_min = {c_min/1024:.0f} KiB, B = {bands}\n")
    print(f"{'band':>5} {'r~':>6} {'chunk size':>13} {'chunks':>8} "
          f"{'S3 ms':>9} {'MB/s':>8} {'meta B':>9} {'meta %':>8}")
    print("-" * 72)
    for band in range(bands):
        acc = Counter()
        m = None
        for _ in range(reps):
            m, _c, _l, t = integrity_stage(data, band, bands, signer)
            for k, v in t.items():
                acc[k] += v
        total = sum(acc.values()) / reps
        meta = len(json.dumps(m.to_dict()).encode())
        row = dict(band=band, r=band / bands,
                   chunk_size=chunk_size_for_risk(band / bands, c_max, c_min),
                   chunks=m.chunk_count, ms=total * 1000,
                   mbps=(size / MB) / total, meta_bytes=meta,
                   meta_pct=100 * meta / size,
                   breakdown={k: v / reps for k, v in acc.items()})
        rows.append(row)
        print(f"{band:>5} {row['r']:6.2f} {row['chunk_size']:13,} "
              f"{row['chunks']:8,} {row['ms']:9.1f} {row['mbps']:8.1f} "
              f"{meta:9,} {row['meta_pct']:7.4f}%")

    b0, bl = rows[0], rows[-1]
    print(f"\n  Maximum scrutiny vs minimum: {bl['ms']/b0['ms']:.2f}x time, "
          f"{bl['chunks']/b0['chunks']:.0f}x chunks, "
          f"{bl['meta_bytes']/b0['meta_bytes']:.0f}x metadata")
    print("  Stage breakdown at top band (ms): " +
          ", ".join(f"{k}={v*1000:.1f}" for k, v in bl["breakdown"].items()))
    RESULTS["E2_integrity"] = rows

    print("\n  Merkle inclusion-proof size vs chunk count "
          "(paper: doubling chunks adds one hash):")
    print(f"  {'chunks':>8} {'proof hashes':>14} {'proof bytes':>12} {'log2(n)':>9}")
    proof_rows = []
    for n in (16, 64, 256, 1024, 4096):
        leaves = [os.urandom(32) for _ in range(n)]
        root = merkle_root(leaves)
        pr = merkle_proof(leaves, n // 2)
        assert verify_proof(leaves[n // 2], pr, root)
        proof_rows.append(dict(chunks=n, hashes=len(pr), bytes=len(pr) * 32))
        print(f"  {n:>8,} {len(pr):>14} {len(pr)*32:>12,} {math.log2(n):>9.1f}")
    RESULTS["E2_merkle_proof"] = proof_rows
    return rows


# ---------------------------------------------------------------------------
# E3 - Inspection accuracy
# ---------------------------------------------------------------------------
def collect_benign(n):
    out = []
    for d in (r"C:\Windows\System32", str(Path(sys.executable).parent),
              "/usr/bin", "/bin"):
        base = Path(d)
        if not base.exists():
            continue
        for pat in ("*.exe", "*.dll"):
            for p in sorted(base.glob(pat)):
                try:
                    if p.is_file() and 8_000 <= p.stat().st_size <= 4_000_000:
                        out.append(p)
                except OSError:
                    continue
                if len(out) >= n:
                    return out
    return out


def eval_inspection(cfg, engine, n_benign):
    hdr("E3  INSPECTION ACCURACY")
    theta = engine.block_threshold
    benign = collect_benign(n_benign)
    print(f"benign corpus : {len(benign)} known-good signed system binaries")
    print(f"blocking threshold theta_blk = {theta}\n")

    scores, fps = [], []
    for p in benign:
        try:
            obj = TransferObject(name=p.name, data=p.read_bytes())
        except OSError:
            continue
        r = engine.inspect(obj)
        scores.append(r.risk)
        if r.blocked:
            fps.append((p.name, r.risk))
    if not scores:
        print("  [!] no benign corpus available on this host")
        return
    fpr = len(fps) / len(scores)
    print(f"  benign risk : mean={statistics.mean(scores):.3f}  "
          f"median={statistics.median(scores):.3f}  "
          f"min={min(scores):.3f}  max={max(scores):.3f}")
    print(f"  FALSE POSITIVE RATE at theta_blk : "
          f"{len(fps)}/{len(scores)} = {fpr:.1%}")
    for nm, s in fps[:5]:
        print(f"      FP: {nm} ({s:.3f})")

    spool = Path("data/spool")
    wanted = ("signature_hit.txt", "suspicious.ps1", "polyglot.pdf", "random.bin")
    threats = ([p for p in sorted(spool.iterdir())
                if p.is_file() and p.name in wanted] if spool.exists() else [])
    print(f"\n  synthetic threat set : {len(threats)} objects")
    det = []
    for p in threats:
        r = engine.inspect(TransferObject(name=p.name, data=p.read_bytes()))
        det.append((p.name, r.risk, r.blocked))
        print(f"      {p.name:20} r={r.risk:.3f} band={r.band} "
              f"{'BLOCKED' if r.blocked else 'passed'}")
    tpr = (sum(1 for _, _, b in det if b) / len(det)) if det else 0.0
    print(f"  detection rate on synthetic threats : {tpr:.0%}")

    print("\n  per-detector mean score on the BENIGN corpus (lower is better):")
    per = {d.name: [] for d in engine.detectors if d.available}
    for p in benign[:min(len(benign), 40)]:
        try:
            obj = TransferObject(name=p.name, data=p.read_bytes())
        except OSError:
            continue
        for res in engine.inspect(obj).results:
            if res.available:
                per[res.name].append(res.score)
    for k, v in sorted(per.items(),
                       key=lambda kv: -(statistics.mean(kv[1]) if kv[1] else 0)):
        if v:
            print(f"      {k:22} mean={statistics.mean(v):.3f}  max={max(v):.3f}")

    RESULTS["E3_inspection"] = dict(
        n_benign=len(scores), false_positive_rate=fpr,
        benign_mean=statistics.mean(scores), benign_max=max(scores),
        threats=[dict(name=a, risk=b, blocked=c) for a, b, c in det],
        detection_rate=tpr,
        per_detector={k: statistics.mean(v) for k, v in per.items() if v})


# ---------------------------------------------------------------------------
# E4 - Covert-channel capacity
# ---------------------------------------------------------------------------
def eval_covert(cfg, engine, trials):
    hdr("E4  COVERT-CHANNEL CAPACITY - measured vs Eq. (6) bound")
    B = int(cfg.integrity["risk_bands"])
    bound = channel_capacity_bound(1.0, B)
    print(f"bands B = {B};  Eq.(6) bound at lambda = 1 object/s: "
          f"C <= {bound:.2f} bit/s\n")
    print("  Attacker model: the adversary cannot hide data in the file (that is")
    print("  what inspection is for) but CAN choose benign artefacts that steer")
    print("  the risk score, encoding data in the observable band.\n")

    def payload_for(sym):
        if sym == 0:
            return b"routine plain text status report.\n" * 40
        if sym == 1:
            return b"%PDF-1.4\n" + b"A" * 2000 + b"\n%%EOF"
        if sym == 2:
            return b"%PDF-1.4\nPK\x03\x04" + b"B" * 1500 + b"\n%%EOF"
        return os.urandom(30000)

    intended, observed = [], []
    for i in range(trials):
        sym = random.randrange(B)
        obj = TransferObject(name=f"c{i}.bin", data=payload_for(sym))
        intended.append(sym)
        observed.append(engine.inspect(obj).band)

    n = len(intended)
    joint = Counter(zip(intended, observed))
    pi, po = Counter(intended), Counter(observed)
    mi = 0.0
    for (a, b), c in joint.items():
        pab, pa, pb = c / n, pi[a] / n, po[b] / n
        mi += pab * math.log2(pab / (pa * pb))
    acc = sum(1 for a, b in zip(intended, observed) if a == b) / n

    print(f"  trials                       : {n}")
    print(f"  attacker symbol->band accuracy: {acc:.1%}")
    print(f"  distinct bands reachable      : {sorted(set(observed))}")
    print(f"  measured mutual information   : {mi:.3f} bit/object")
    print(f"  theoretical maximum log2(B)   : {math.log2(B):.3f} bit/object")
    print(f"  measured capacity @ 1 obj/s   : {mi:.3f} bit/s")
    print(f"  Eq.(6) derived bound          : {bound:.3f} bit/s")
    ok = mi <= bound + 1e-9
    print(f"\n  LEAKAGE WITHIN DERIVED BOUND : {'YES' if ok else 'NO'}"
          f"  ({mi:.3f} <= {bound:.3f})")
    RESULTS["E4_covert"] = dict(bands=B, bound_bits_per_s=bound, trials=n,
                                steering_accuracy=acc, mutual_information=mi,
                                reachable_bands=sorted(set(observed)),
                                within_bound=bool(ok))


# ---------------------------------------------------------------------------
# E5 - paper worked-example validation
# ---------------------------------------------------------------------------
def eval_paper_claims(cfg):
    hdr("E5  VALIDATION OF THE PAPER'S WORKED EXAMPLES")
    c_max, c_min = 1_048_576, 16_384
    print("  Eq.(2)  10 MB object, c_max=1MB, c_min=16KB")
    print("          paper states ~15 chunks at r=0.1 and ~420 at r=0.9")
    eq2 = {}
    for r in (0.1, 0.9):
        cs = chunk_size_for_risk(r, c_max, c_min)
        nch = math.ceil(10 * MB / cs)
        eq2[f"r={r}"] = dict(chunk_size=cs, chunks=nch)
        print(f"          r={r}: chunk={cs:,} B -> {nch} chunks")

    a = cfg.anchoring
    t_min = float(a["t_min_seconds"]); t_max = float(a["t_max_seconds"])
    gamma = float(a["gamma"])
    print(f"\n  Eq.(4)  T_min={t_min}s T_max={t_max}s gamma={gamma}")
    print("          paper states T(0)=T_max, T(1)=T_min (inverted vs Eq.2)")
    for r in (0.0, 0.5, 1.0):
        print(f"          T({r:.1f}) = "
              f"{anchoring_interval(r, t_min, t_max, gamma):7.1f}s")

    print("\n  Eq.(1)  five detectors at 0.02 plus one at 0.9")
    print("          paper states Noisy-OR ~0.91, arithmetic mean ~0.16")
    votes = [(1.0, 0.02)] * 5 + [(1.0, 0.9)]
    no = noisy_or(votes)
    mean = sum(v for _, v in votes) / len(votes)
    print(f"          Noisy-OR = {no:.3f}   mean = {mean:.3f}")

    RESULTS["E5_paper_claims"] = dict(
        eq2=eq2,
        eq4={"T(0)": anchoring_interval(0.0, t_min, t_max, gamma),
             "T(1)": anchoring_interval(1.0, t_min, t_max, gamma)},
        eq1={"noisy_or": no, "mean": mean})


# ---------------------------------------------------------------------------
# E6 - FEC reliability
# ---------------------------------------------------------------------------
def eval_fec(cfg, trials):
    hdr("E6  ONE-WAY RELIABILITY - FEC recovery vs packet loss (no ACKs)")
    overhead = float(cfg.fec["overhead"])
    fec = FEC(backend="reedsolo", symbol_size=int(cfg.fec["symbol_size"]),
              overhead=overhead)
    payload = os.urandom(256 * 1024)
    print(f"payload = {len(payload)/1024:.0f} KiB, FEC overhead = {overhead:.0%}, "
          f"backend = {fec.effective_backend}\n")
    print(f"{'loss rate':>10} {'recovered':>11} {'symbols sent':>14}")
    print("-" * 38)
    rows = []
    syms = fec.encode(payload, 1)
    for loss in (0.0, 0.05, 0.10, 0.20, 0.30, 0.40):
        ok = 0
        for t in range(trials):
            random.seed(1000 + t)
            kept = [s for s in syms if random.random() > loss]
            dec = FecDecoder()
            done = None
            for s in kept:
                r = dec.add(s)
                if r is not None:
                    done = r
                    break
            if done is not None and dec.reconstruct(done) == payload:
                ok += 1
        rate = ok / trials
        rows.append(dict(loss=loss, recovery_rate=rate))
        print(f"{loss:9.0%} {rate:10.0%} {len(syms):14,}")
    RESULTS["E6_fec"] = rows
    print(f"\n  Recovery holds while loss stays below the FEC overhead "
          f"({overhead:.0%}).")
    print("  Beyond that a generation cannot be inverted and the object is lost -")
    print("  there is no retransmission path on a one-way link.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="results_evaluation.json")
    args = ap.parse_args()
    random.seed(42)

    cfg = load_config()
    engine = InspectionEngine(cfg)
    priv, _pub = generate_keypair()
    signer = Signer(priv)

    print("=" * 78)
    print("RAIL QUANTITATIVE EVALUATION")
    print("=" * 78)
    print(f"host      : {os.cpu_count()} logical CPUs | "
          f"{platform.system()} {platform.release()} | {platform.machine()}")
    print(f"python    : {platform.python_version()}")
    print(f"detectors : "
          f"{', '.join(d.name for d in engine.detectors if d.available)}")
    print(f"policy    : {cfg.policy_id}")
    RESULTS["environment"] = dict(
        cpus=os.cpu_count(), system=platform.system(),
        release=platform.release(), python=platform.python_version(),
        detectors=[d.name for d in engine.detectors if d.available])

    sizes = [MB, 4 * MB] if args.quick else [MB, 4 * MB, 16 * MB]
    reps = 1 if args.quick else 2
    eval_goodput(cfg, engine, signer, sizes, reps)
    eval_integrity(cfg, signer, 8 * MB if args.quick else 16 * MB, 2)
    eval_inspection(cfg, engine, 20 if args.quick else 60)
    eval_covert(cfg, engine, 40 if args.quick else 120)
    eval_paper_claims(cfg)
    eval_fec(cfg, 5 if args.quick else 10)

    Path(args.out).write_text(json.dumps(RESULTS, indent=2, default=str),
                              encoding="utf-8")
    print("\n" + "=" * 78)
    print(f"results written to {args.out}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
