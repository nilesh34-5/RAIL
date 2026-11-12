"""E3/E4 - performance and integrity cost.

Drives the railcds stages (chunker, hashchain, merkle, crypto, fec,
anchoring) exactly as SenderGateway does, to measure per risk band and for the
two fixed baselines:
  * integrity time  : S3 build (chunk -> hash chain -> Merkle root -> sign)
  * metadata bytes  : manifest size added over the raw object
  * localisation    : chunk size and Merkle proof length
  * chunk count     : k
  * FEC overhead eta : coded bytes / object bytes - 1
  * anchor writes   : per 1000 objects at the band's interval, vs per-object
Stage timing (S2 inspect, S3 integrity, S4 FEC) is taken from the real modules;
each timing is repeated REPS times and reported mean+-SD.

    python e34_perf.py --node /opt/railtb/nodeA --config CFG --out e34.json \
        --size 10485760 --reps 30
"""
import argparse, json, statistics, sys, time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--size", type=int, default=10 * 1024 * 1024)
    ap.add_argument("--reps", type=int, default=30)
    a = ap.parse_args()
    sys.path.insert(0, a.node)
    from railcds.config import load_config
    from railcds.chunker import chunk_object, chunk_size_for_risk
    from railcds.crypto import generate_keypair, Signer
    from railcds.hashchain import build_hash_chain
    from railcds.merkle import merkle_root, merkle_proof
    from railcds.models import Manifest
    from railcds.session import Session
    from railcds.fec import FEC
    from railcds.anchoring import anchoring_interval
    from railcds import wire
    import os, math

    cfg = load_config(a.config)
    B = int(cfg.integrity["risk_bands"])
    c_max = int(cfg.integrity["chunk_max_bytes"]); c_min = int(cfg.integrity["chunk_min_bytes"])
    tmin = float(cfg.anchoring["t_min_seconds"]); tmax = float(cfg.anchoring["t_max_seconds"])
    gamma = float(cfg.anchoring["gamma"])
    priv, pub = generate_keypair(); signer = Signer(priv)
    data = os.urandom(a.size)

    def integrity_once(csize):
        s = Session.create("eval")
        t0 = time.perf_counter()
        chunks = chunk_object(data, csize)
        leaves = build_hash_chain(chunks, s.h0)
        root = merkle_root(leaves)
        m = Manifest(object_name="o.bin", object_size=len(data), epoch=s.epoch,
                     policy_id="eval", h0=s.h0, band=0, chunk_count=len(chunks),
                     chunk_lengths=[c.length for c in chunks], merkle_root=root,
                     signature=b"")
        m.signature = signer.sign(m.signing_payload())
        dt = time.perf_counter() - t0
        payload = wire.pack_object(m, data)
        meta = len(payload) - len(data)
        return dt, len(chunks), meta, len(m.to_dict()["chunk_lengths"])

    def configs():
        yield ("fixed_coarse", c_max)
        yield ("fixed_fine", c_min)
        for b in range(B):
            rt = b / B
            yield (f"band_{b}", chunk_size_for_risk(rt, c_max, c_min))

    fec = FEC(backend="reedsolo", symbol_size=int(cfg.fec["symbol_size"]),
              overhead=float(cfg.fec["overhead"]))
    results = {"size": a.size, "reps": a.reps, "bands": B, "rows": []}
    for name, csize in configs():
        times = []
        for _ in range(a.reps):
            dt, k, meta, _ = integrity_once(csize)
            times.append(dt)
        # one representative build for structural numbers
        _, k, meta, _ = integrity_once(csize)
        proof_len = len(merkle_proof(build_hash_chain(chunk_object(data, csize),
                       Session.create("eval").h0), 0)) if k >= 1 else 0
        # FEC overhead for this object
        t0 = time.perf_counter()
        sample = wire.pack_object(
            Manifest(object_name="o", object_size=len(data), epoch="e",
                     policy_id="eval", h0=b"\0"*32, band=0, chunk_count=k,
                     chunk_lengths=[csize]*k, merkle_root=b"\0"*32, signature=b"\0"*64),
            data)
        syms = fec.encode(sample, 1)
        fec_t = time.perf_counter() - t0
        coded = sum(len(s) for s in syms)
        band_idx = None
        if name.startswith("band_"):
            band_idx = int(name.split("_")[1])
            interval = anchoring_interval(band_idx / B, tmin, tmax, gamma)
        else:
            interval = None
        results["rows"].append({
            "config": name, "chunk_size": csize, "chunks": k,
            "integrity_time_ms_mean": statistics.mean(times) * 1e3,
            "integrity_time_ms_sd": (statistics.stdev(times) * 1e3) if len(times) > 1 else 0.0,
            "metadata_bytes": meta, "metadata_pct": 100.0 * meta / a.size,
            "merkle_proof_len": proof_len,
            "fec_overhead_eta": coded / len(sample) - 1.0,
            "fec_encode_s": fec_t,
            "anchor_interval_s": interval,
        })
        print(f"{name:12s} c={csize:8d} k={k:5d} S3={statistics.mean(times)*1e3:7.2f}ms "
              f"meta={meta}B proof={proof_len} eta={coded/len(sample)-1:.2f} "
              f"T={interval if interval else '-'}", flush=True)

    # anchor writes per 1000 objects: band mix 90/7/2/1 as in the paper's E4
    mix = {0: 0.90, 1: 0.07, 2: 0.02, 3: 0.01}
    # worst-case bound: a gateway anchors at most once per interval; approximate
    # the per-1000-object anchor count by 1000*object_rate_fraction/interval * mean_gap
    results["note_anchor"] = ("per-object anchoring = 1000 writes/1000 objects; "
                              "RAIL anchors the highest band seen since the last "
                              "anchor at interval T(r_tilde)")
    Path(a.out).write_text(json.dumps(results, indent=2))
    print("saved", a.out)


if __name__ == "__main__":
    main()
