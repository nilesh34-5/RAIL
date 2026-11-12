"""E6 - tampering and replay detection over the wire (sender side).

Builds genuine signed objects with the railcds crypto/FEC, injects ONE attack
type, and transmits the (possibly tampered) FEC symbols across the real link to
the ReceiverGateway. One attack per run so the receiver's
verdicts (rx.jsonl) attribute unambiguously. "Detected" = the bad object is NOT
delivered (either rejected at S5 or lost in FEC reconstruction); "delivered" =
accepted.  Run inside netns netA.
"""
import argparse, json, os, sys, time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=52080)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--warm", default=None)
    ap.add_argument("--go", default=None)
    a = ap.parse_args()
    sys.path.insert(0, a.node)
    from railcds.config import load_config
    from railcds.crypto import generate_keypair, Signer
    from railcds.chunker import chunk_object, chunk_size_for_risk
    from railcds.hashchain import build_hash_chain
    from railcds.merkle import merkle_root
    from railcds.models import Manifest
    from railcds.session import Session
    from railcds.fec import FEC
    from railcds import wire
    from railcds.transport import UdpSender

    cfg = load_config(a.config)
    signer = Signer.from_file(cfg.resolve(cfg.crypto["sender_private_key"]))
    wrong_priv, _ = generate_keypair(); wrong_signer = Signer(wrong_priv)
    bands = int(cfg.integrity["risk_bands"])
    c_max = int(cfg.integrity["chunk_max_bytes"]); c_min = int(cfg.integrity["chunk_min_bytes"])
    band = 2
    cs = chunk_size_for_risk(band / bands, c_max, c_min)
    fec = FEC(backend="reedsolo", symbol_size=int(cfg.fec["symbol_size"]),
              overhead=float(cfg.fec["overhead"]))
    sender = UdpSender(a.host, a.port, 0.3)
    oid = [0]
    base = (("benign object for integrity test. " * 20 + "\n") * 2000).encode()  # ~1.3 MB

    def sign_payload(data, name, forged=False):
        s = Session.create(cfg.policy_id)
        chunks = chunk_object(data, cs)
        leaves = build_hash_chain(chunks, s.h0)
        root = merkle_root(leaves)
        m = Manifest(object_name=name, object_size=len(data), epoch=s.epoch,
                     policy_id=cfg.policy_id, h0=s.h0, band=band,
                     chunk_count=len(chunks), chunk_lengths=[c.length for c in chunks],
                     merkle_root=root, signature=b"")
        m.signature = (wrong_signer if forged else signer).sign(m.signing_payload())
        return bytearray(wire.pack_object(m, data)), s

    def send(payload, oid_reuse=None):
        oid[0] += 1
        for sym in fec.encode(bytes(payload), oid[0]):
            sender.send(sym)
        time.sleep(0.2)

    if a.warm:
        open(a.warm, "w").write(str(time.time()))
    if a.go:
        for _ in range(6000):
            if os.path.exists(a.go):
                break
            time.sleep(0.05)

    for i in range(a.n):
        nm = f"{a.attack}_{i}"
        if a.attack == "baseline":
            p, _ = sign_payload(base, nm); send(p)
        elif a.attack == "bitflip":
            p, _ = sign_payload(base, nm); p[-50] ^= 0xFF; send(p)
        elif a.attack == "truncation":
            p, _ = sign_payload(base, nm); send(p[:-cs])          # drop last chunk bytes
        elif a.attack == "forged_sig":
            p, _ = sign_payload(base, nm, forged=True); send(p)
        elif a.attack == "chunk_swap":
            p, _ = sign_payload(base, nm)
            mlen = int.from_bytes(p[:4], "big")
            obj = bytearray(base)
            obj[0:cs], obj[cs:2*cs] = base[cs:2*cs], base[0:cs]   # swap first two chunks
            send(p[:4+mlen] + bytes(obj))
        elif a.attack == "split_merge":
            p, _ = sign_payload(base, nm)
            mlen = int.from_bytes(p[:4], "big")
            md = json.loads(p[4:4+mlen]); cl = md["chunk_lengths"]
            cl[0] += cl[1]; del cl[1]; md["chunk_count"] = len(cl)
            nm2 = json.dumps(md, separators=(",", ":")).encode()
            send(len(nm2).to_bytes(4, "big") + nm2 + p[4+mlen:])
        elif a.attack == "replay":
            p, _ = sign_payload(base, nm)
            send(p); send(p)                                      # 2nd = replay
    sender.close()
    print(f"E6 sender done: attack={a.attack} n={a.n}")


if __name__ == "__main__":
    main()
