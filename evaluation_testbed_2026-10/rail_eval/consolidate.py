"""Consolidate E1-E7 raw outputs into results/summary.json with the statistics
the paper tables need (means, SDs, Wilson 95% CIs for proportions)."""
import json, math, statistics
from collections import defaultdict
from pathlib import Path

R = Path("results")


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


s = {}

# E1
s["E1"] = json.loads((R / "e1" / "e1.json").read_text())

# E2: aggregate delivery ratio per (backend, model, rate, repeat)
e2 = [json.loads(l) for l in (R / "e2" / "e2.jsonl").read_text().splitlines()]
agg = defaultdict(list)
for r in e2:
    agg[(r["backend"], r["model"], r["rate"], r["repeat"])].append(r["delivered"] / r["n_objects"])
e2rows = []
for (be, mo, ra, rp), ds in sorted(agg.items()):
    k = sum(round(d * e2[0]["n_objects"]) for d in ds)
    ntot = len(ds) * e2[0]["n_objects"]
    lo, hi = wilson(sum(int(round(d * e2[0]["n_objects"])) for d in ds), ntot)
    e2rows.append({"backend": be, "model": mo, "rate": ra, "repeat": rp,
                   "mean_delivery": statistics.mean(ds),
                   "sd": statistics.pstdev(ds) if len(ds) > 1 else 0.0,
                   "wilson95": [lo, hi], "reps": len(ds),
                   "eta": next(x["fec_overhead_eta"] for x in e2
                              if x["backend"] == be and x["repeat"] == rp)})
s["E2"] = e2rows

# E3/E4
s["E34"] = json.loads((R / "e34.json").read_text())
s["E3_stage"] = json.loads((R / "e3_stage.json").read_text())
s["E3_wire_goodput"] = []
if (R / "e3wire" / "tx.jsonl").exists():
    for l in (R / "e3wire" / "tx.jsonl").read_text().splitlines():
        t = json.loads(l)
        if t.get("status") == "SENT":
            s["E3_wire_goodput"].append({"object": t["object"], "size": t["size"],
                "wall_s": t["_wall_s"], "goodput_MBps": (t["size"] / 1048576) / t["_wall_s"],
                "band": t["band"], "chunks": t["chunk_count"]})

# E5
s["E5"] = json.loads((R / "e5_metrics.json").read_text())

# E6
s["E6"] = [json.loads(l) for l in (R / "e6" / "e6.jsonl").read_text().splitlines()]

# E7
s["E7"] = json.loads((R / "e7.json").read_text())

Path("results/summary.json").write_text(json.dumps(s, indent=2))
print("wrote results/summary.json")
# print a few key reliability aggregates
print("\nE2 delivery (mean over reps):")
for r in s["E2"]:
    if r["model"] != "none":
        print(f"  {r['backend']:8s} {r['model']:6s} loss={r['rate']*100:3.0f}% rep{r['repeat']} "
              f"D={r['mean_delivery']*100:5.1f}% CI[{r['wilson95'][0]*100:.0f},{r['wilson95'][1]*100:.0f}] eta={r['eta']:.2f}")
