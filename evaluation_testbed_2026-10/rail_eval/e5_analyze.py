"""Analyse E5 - detection accuracy per detector tier and per fusion rule.

Reads results/e5_inspect.jsonl (every object's per-detector scores, the real
noisy-OR fused risk, label 0=benign / 1=non-benign). Computes, at the block
threshold theta_blk and over the full ROC:
  * per tier (structural = protocol_validator+file_type; signature = yara;
    ML = ember2024+malconv+malconvgct) the tier score = max of its detectors
  * fusion rules: mean, maximum, noisy-OR (RAIL's own fused risk)
  * TPR, FPR, F1 at theta_blk; AUC; mean inspect time/object
Also the benign-only false-positive analysis (the meaningful real-data number).
"""
import argparse, json, math, statistics
from pathlib import Path


def roc_auc(scores, labels):
    pairs = sorted(zip(scores, labels), key=lambda x: x[0])
    P = sum(labels); N = len(labels) - P
    if P == 0 or N == 0:
        return float("nan")
    # rank-sum (Mann-Whitney) AUC with tie handling
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores); i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        r = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = r
        i = j + 1
    sum_pos = sum(ranks[i] for i in range(len(scores)) if labels[i] == 1)
    return (sum_pos - P * (P + 1) / 2) / (P * N)


def metrics_at(scores, labels, thr):
    TP = sum(1 for s, l in zip(scores, labels) if s >= thr and l == 1)
    FP = sum(1 for s, l in zip(scores, labels) if s >= thr and l == 0)
    TN = sum(1 for s, l in zip(scores, labels) if s < thr and l == 0)
    FN = sum(1 for s, l in zip(scores, labels) if s < thr and l == 1)
    tpr = TP / (TP + FN) if TP + FN else float("nan")
    fpr = FP / (FP + TN) if FP + TN else float("nan")
    f1 = 2 * TP / (2 * TP + FP + FN) if (2 * TP + FP + FN) else float("nan")
    return dict(TP=TP, FP=FP, TN=TN, FN=FN, TPR=tpr, FPR=fpr, F1=f1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--e5", default="results/e5_inspect.jsonl")
    ap.add_argument("--out", default="results/e5_metrics.json")
    ap.add_argument("--theta", type=float, default=0.90)
    a = ap.parse_args()
    rows = [json.loads(l) for l in Path(a.e5).read_text().splitlines()]
    labels = [r["label"] for r in rows]

    tiers = {
        "structural": ["protocol_validator", "file_type"],
        "signature_yara": ["yara_signature"],
        "ml_lightgbm_cnn": ["ember2024_ml", "malconv_ml", "malconvgct_ml"],
    }
    def tier_score(r, dets):
        return max((r["det"].get(d, {}).get("s", 0.0) for d in dets), default=0.0)

    result = {"n": len(rows), "n_benign": labels.count(0), "n_positive": labels.count(1),
              "theta_blk": a.theta, "tiers": {}, "fusion": {}}

    for name, dets in tiers.items():
        sc = [tier_score(r, dets) for r in rows]
        m = metrics_at(sc, labels, a.theta); m["AUC"] = roc_auc(sc, labels)
        result["tiers"][name] = m

    # fusion rules over ALL available detectors
    def all_scores(r): return [(d["s"], d["w"]) for d in r["det"].values() if d.get("ok")]
    mean_sc = [statistics.mean([s for s, _ in all_scores(r)]) if all_scores(r) else 0 for r in rows]
    max_sc = [max([s for s, _ in all_scores(r)], default=0) for r in rows]
    nor_sc = [r["risk"] for r in rows]           # RAIL's own noisy-OR fused risk
    for name, sc in [("mean", mean_sc), ("maximum", max_sc), ("noisy_or_RAIL", nor_sc)]:
        m = metrics_at(sc, labels, a.theta); m["AUC"] = roc_auc(sc, labels)
        result["fusion"][name] = m

    # timing
    ts = [r["t_inspect_s"] for r in rows]
    result["inspect_ms_mean"] = statistics.mean(ts) * 1e3
    result["inspect_ms_median"] = statistics.median(ts) * 1e3

    # benign-only FPR of the fused score at theta (the real-data number)
    benign_risk = [r["risk"] for r in rows if r["label"] == 0]
    result["benign_only"] = {
        "n": len(benign_risk), "risk_mean": statistics.mean(benign_risk),
        "risk_max": max(benign_risk),
        "false_positives_at_theta": sum(1 for x in benign_risk if x >= a.theta),
        "fpr_pct": 100.0 * sum(1 for x in benign_risk if x >= a.theta) / len(benign_risk)}
    # per class benign risk
    by_cls = {}
    for r in rows:
        if r["label"] == 0:
            by_cls.setdefault(r["class"], []).append(r["risk"])
    result["benign_by_class"] = {c: {"n": len(v), "mean": statistics.mean(v),
                                     "max": max(v)} for c, v in sorted(by_cls.items())}

    Path(a.out).write_text(json.dumps(result, indent=2))
    print(f"n={result['n']} benign={result['n_benign']} pos={result['n_positive']} theta={a.theta}")
    print("\nTIERS (score = max over tier detectors):")
    for n, m in result["tiers"].items():
        print(f"  {n:16s} TPR={m['TPR']*100:5.1f}% FPR={m['FPR']*100:5.2f}% F1={m['F1']:.3f} AUC={m['AUC']:.3f}")
    print("FUSION:")
    for n, m in result["fusion"].items():
        print(f"  {n:16s} TPR={m['TPR']*100:5.1f}% FPR={m['FPR']*100:5.2f}% F1={m['F1']:.3f} AUC={m['AUC']:.3f}")
    b = result["benign_only"]
    print(f"\nBenign corpus: n={b['n']} risk mean={b['risk_mean']:.3f} max={b['risk_max']:.3f} "
          f"FP@theta={b['false_positives_at_theta']} FPR={b['fpr_pct']:.2f}%")
    print(f"inspect/object mean={result['inspect_ms_mean']:.1f} ms median={result['inspect_ms_median']:.1f} ms")
    print("\nbenign risk by class:")
    for c, v in result["benign_by_class"].items():
        print(f"  {c:10s} n={v['n']:4d} mean={v['mean']:.3f} max={v['max']:.3f}")


if __name__ == "__main__":
    main()
