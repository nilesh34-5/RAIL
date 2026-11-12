"""E7 - metadata covert-channel capacity.

Threat (paper Sec. T5): an attacker in network A steers the risk BAND of each
object with crafted benign files; a colluder in B reads the band off the
observable chunk count. Band quantisation (Eq. band) is supposed to cap the leak
at log2(B) bits/object and the token bucket caps the rate, giving C <= lambda*log2(B).

We measure the REAL channel using the real risk scores produced by RAIL's own
InspectionEngine over the benign corpus (file results/e5_inspect.jsonl). The
attacker's strategy is realistic: to signal symbol X it emits a file of the type
whose modal band is X (a type->band codebook built from the corpus). RAIL then
assigns the actual band Y; because type->band is noisy, I(X;Y) < log2(B).

Outputs, for B in {2,4,8,16}:
  * measured leakage  Chat = lambda * Ihat(X;Y)   (Miller-Madow MI + bootstrap CI)
  * the bound         lambda * log2(B)
  * with chunk-count padding (Y = band only) vs without (Y = raw chunk count,
    so object-size variation adds bits) -- shows padding keeps Y within the bound
and the unquantised baseline: entropy of the chunk count when chunk size follows
the CONTINUOUS score (the ~9 bit/object leak RAIL prevents).

    python e7_covert.py --e5 results/e5_inspect.jsonl --out results/e7.json \
        --lambda 1.0 --trials 4000
"""
import argparse, json, math, random
from collections import defaultdict, Counter
from pathlib import Path


def quantise_band(risk, B):
    idx = int(math.floor(min(max(risk, 0.0), 1.0) * B))
    return min(idx, B - 1)


def mi_miller_madow(pairs, bx, by):
    n = len(pairs)
    jx = Counter(pairs); mx = Counter(x for x, _ in pairs); my = Counter(y for _, y in pairs)
    mi = 0.0
    for (x, y), c in jx.items():
        pxy = c / n; px = mx[x] / n; py = my[y] / n
        mi += pxy * math.log2(pxy / (px * py))
    # Miller-Madow bias correction: + (|supp_xy| - |supp_x| - |supp_y| + 1)/(2 n ln2)
    corr = (len(jx) - len(mx) - len(my) + 1) / (2 * n * math.log(2))
    return max(0.0, mi - corr)


def chunk_count(size, csize):
    return max(1, math.ceil(size / csize))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--e5", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--lam", type=float, default=1.0)
    ap.add_argument("--trials", type=int, default=4000)
    ap.add_argument("--c_max", type=int, default=1048576)
    ap.add_argument("--c_min", type=int, default=16384)
    a = ap.parse_args()
    rng = random.Random(7)

    rows = [json.loads(l) for l in Path(a.e5).read_text().splitlines()]
    rows = [r for r in rows if r.get("label") == 0]        # benign only (the attacker's palette)
    risks = [(r["risk"], r["class"], r["size"]) for r in rows]

    out = {"lambda": a.lam, "trials": a.trials, "n_corpus": len(risks), "per_B": []}

    for B in (2, 4, 8, 16):
        # type -> band distribution, then codebook: band -> best type for that band
        by_type = defaultdict(list)
        for risk, cls, _ in risks:
            by_type[cls].append(quantise_band(risk, B))
        # for each target band, the type whose files most often land in it
        type_band_count = {t: Counter(bs) for t, bs in by_type.items()}
        codebook = {}
        for band in range(B):
            best_t, best_n = None, -1
            for t, cnt in type_band_count.items():
                if cnt[band] > best_n:
                    best_n, best_t = cnt[band], t
            codebook[band] = best_t
        reachable = sorted({quantise_band(r, B) for r, _, _ in risks})
        files_by_type = defaultdict(list)
        for risk, cls, size in risks:
            files_by_type[cls].append((risk, size))

        # simulate the band channel: attacker emits a file targeting band X,
        # RAIL assigns actual band Y (padded -> receiver sees exactly the band).
        pairs_pad = []
        # stronger adversary that ALSO modulates object size into G buckets to
        # open a within-band sub-channel; padding the chunk count removes it.
        G = 4
        pairs_strong_pad = []    # with padding: receiver sees band only
        pairs_strong_nopad = []  # without padding: receiver sees (band, size bucket)
        for _ in range(a.trials):
            X = rng.randrange(B)
            risk, size = rng.choice(files_by_type[codebook[X]])
            Yband = quantise_band(risk, B)
            pairs_pad.append((X, Yband))
            # strong adversary: intended symbol encodes band(X) and a size bucket g
            g = rng.randrange(G)
            Xs = X * G + g
            csize = int(round(a.c_max * (a.c_min / a.c_max) ** (Yband / B)))
            csize = max(a.c_min, min(a.c_max, csize))
            # size bucket realised as a chunk-count offset the attacker induces
            size_g = a.c_min * (1 + g) + Yband  # a size the attacker can pick
            cc = chunk_count(size_g * 4, csize)
            pairs_strong_pad.append((Xs, Yband))              # padded: only band visible
            pairs_strong_nopad.append((Xs, (Yband, cc)))      # unpadded: band+count visible

        mi_pad = mi_miller_madow(pairs_pad, B, B)
        mi_strong_pad = mi_miller_madow(pairs_strong_pad, B * G, B)
        mi_strong_nopad = mi_miller_madow(pairs_strong_nopad, B * G, B * 50)
        mi_nopad = mi_strong_nopad
        # bootstrap 95% CI for the padded (RAIL) estimate
        boots = []
        for _ in range(300):
            samp = [rng.choice(pairs_pad) for _ in range(len(pairs_pad))]
            boots.append(mi_miller_madow(samp, B, B))
        boots.sort()
        lo, hi = boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]
        bound = math.log2(B)
        out["per_B"].append({
            "B": B, "bound_bits": bound, "bound_Cbps": a.lam * bound,
            "reachable_bands": reachable, "n_reachable": len(reachable),
            "mi_padded_bits": mi_pad, "C_padded_bps": a.lam * mi_pad,
            "ci95": [a.lam * lo, a.lam * hi],
            "mi_strong_padded_bits": mi_strong_pad,
            "mi_strong_nopadding_bits": mi_nopad,
            "within_bound_padded": mi_pad <= bound + 1e-9,
            "strong_padded_within_bound": mi_strong_pad <= bound + 1e-9,
            "strong_nopadding_exceeds_bound": mi_nopad > bound + 1e-9,
            "pct_of_bound_padded": 100.0 * mi_pad / bound,
        })
        print(f"B={B:2d} bound={bound:.2f}b  RAIL(band,padded)={mi_pad:.3f}b "
              f"[{lo:.3f},{hi:.3f}]  strong+pad={mi_strong_pad:.3f}b "
              f"strong–nopad={mi_nopad:.3f}b  reach={len(reachable)}/{B}")

    # unquantised baseline: chunk size from the CONTINUOUS score -> chunk-count entropy
    fixed_size = 10 * 1024 * 1024
    ccs = []
    for risk, _, _ in risks:
        csize = int(round(a.c_max * (a.c_min / a.c_max) ** min(max(risk, 0), 1)))
        csize = max(a.c_min, min(a.c_max, csize))
        ccs.append(chunk_count(fixed_size, csize))
    n = len(ccs); cnt = Counter(ccs)
    H = -sum((c / n) * math.log2(c / n) for c in cnt.values())
    out["unquantised_baseline"] = {
        "object_size": fixed_size, "distinct_chunk_counts": len(cnt),
        "chunk_count_entropy_bits": H,
        "note": "continuous-score chunking leaks this many bits/object; RAIL caps it at log2(B)"}
    print(f"\nunquantised continuous-score chunking: H(chunk_count)={H:.2f} bits/object "
          f"({len(cnt)} distinct counts)")
    Path(a.out).write_text(json.dumps(out, indent=2))
    print("saved", a.out)


if __name__ == "__main__":
    main()
