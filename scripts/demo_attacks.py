"""Security demonstration: empirically exercise the paper's threat model.

    python scripts/demo_attacks.py

Section II of the paper lists five adversary objectives.  This script mounts a
concrete attack for each one against the real RAIL code paths and reports
whether the architecture detects or bounds it.  It is the evaluation companion
to scripts/demo_local.py (which shows the benign happy path).

  T1  Reverse information flow      - structural: no return path exists
  T2  Malicious payload injection   - Stage S2 inspection must quarantine
  T3  Data corruption after inspect - Merkle root mismatch must reject
  T4  Replay / reordering           - session binding + seq binding must reject
  T5  Metadata covert channel       - quantisation must bound capacity (Eq. 6)
"""
import os
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
warnings.simplefilter("ignore")

from railcds import wire                                    # noqa: E402
from railcds.chunker import chunk_object, chunk_size_for_risk  # noqa: E402
from railcds.config import load_config                      # noqa: E402
from railcds.crypto import generate_keypair, Signer, Verifier  # noqa: E402
from railcds.hashchain import build_hash_chain              # noqa: E402
from railcds.inspection.engine import InspectionEngine      # noqa: E402
from railcds.merkle import merkle_root                      # noqa: E402
from railcds.models import Manifest, TransferObject         # noqa: E402
from railcds.quantize import quantise, channel_capacity_bound  # noqa: E402
from railcds.session import Session                         # noqa: E402
from railcds.transport import UdpSender                     # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
results = []


def report(threat, desc, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {threat}  {desc}")
    if detail:
        print(f"         {detail}")


def build(data, band, bands, signer, policy="policy-test", session=None):
    """Produce a signed on-wire payload exactly as Stage S3 would."""
    session = session or Session.create(policy)
    size = chunk_size_for_risk(band / bands, 1_048_576, 16_384)
    chunks = chunk_object(data, size)
    leaves = build_hash_chain(chunks, session.h0)
    root = merkle_root(leaves)
    m = Manifest(object_name="obj.bin", object_size=len(data), epoch=session.epoch,
                 policy_id=policy, h0=session.h0, band=band, chunk_count=len(chunks),
                 chunk_lengths=[c.length for c in chunks], merkle_root=root,
                 signature=b"")
    m.signature = signer.sign(m.signing_payload())
    return wire.pack_object(m, data), session


def verify(payload, verifier):
    """Stage S5: recompute the chain/root and check the signature."""
    manifest, chunks = wire.unpack_object(payload)
    root = merkle_root(build_hash_chain(chunks, manifest.h0))
    return (root == manifest.merkle_root
            and verifier.verify(manifest.signature, manifest.signing_payload()))


def main() -> int:
    print("=" * 74)
    print("RAIL security demonstration - threat model from Section II")
    print("=" * 74)
    priv, pub = generate_keypair()
    signer, verifier = Signer(priv), Verifier(pub)

    # ---- T1: reverse information flow ---------------------------------
    print("\nT1  Reverse information flow")
    sender = UdpSender("127.0.0.1", 52080, 0.0)
    # the gateway never reads from its send socket: assert no read is performed
    src = (Path(__file__).resolve().parent.parent / "railcds" / "sender.py").read_text()
    no_reads = ("recv" not in src)
    sender.close()
    report("T1", "sender gateway performs no receive on the one-way link",
           no_reads, "railcds/sender.py contains no recv/recvfrom call")

    # ---- T2: malicious payload injection -------------------------------
    print("\nT2  Malicious payload injection")
    engine = InspectionEngine(load_config())
    marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    mal = TransferObject(name="invoice.txt", data=("note " + marker).encode())
    rep = engine.inspect(mal)
    report("T2", f"signature-bearing object quarantined (r={rep.risk:.3f})",
           rep.blocked, f"threshold theta_blk={engine.block_threshold}")

    poly = TransferObject(name="doc.pdf",
                          data=b"%PDF-1.4\nbody\nPK\x03\x04zip\nMZ prog\n%%EOF")
    rp = engine.inspect(poly)
    ft = next((d for d in rp.results if d.name == "file_type"), None)
    report("T2", f"polyglot detected by file-type layer (s={ft.score:.2f})",
           bool(ft and ft.score >= 0.5), "Koch et al. polyglot threat")

    # ---- T3: data corruption after inspection --------------------------
    print("\nT3  Data corruption after inspection")
    data = os.urandom(40_000)
    payload, _ = build(data, 1, 4, signer)
    report("T3", "untampered object verifies", verify(payload, verifier))
    tampered = bytearray(payload)
    tampered[-50] ^= 0xFF                       # flip one bit in the payload
    report("T3", "single-bit tamper rejected (Merkle root mismatch)",
           not verify(bytes(tampered), verifier))

    # ---- T4: replay / reordering ---------------------------------------
    print("\nT4  Replay and reordering")
    s1 = Session.create("policy-test")
    s2 = Session.create("policy-test")
    report("T4", "each session derives a unique H0 (replay defence)",
           s1.h0 != s2.h0 and s1.epoch != s2.epoch)

    # reorder two chunks: seq is bound into the chain, so the root changes
    chunks = chunk_object(b"A" * 100 + b"B" * 100, 100)
    root_ok = merkle_root(build_hash_chain(chunks, s1.h0))
    swapped = [chunks[1], chunks[0]]
    root_bad = merkle_root(build_hash_chain(swapped, s1.h0))
    report("T4", "chunk reordering changes the Merkle root", root_ok != root_bad)

    # forged signature with an attacker key
    other_priv, other_pub = generate_keypair()
    forged, _ = build(data, 1, 4, Signer(other_priv))
    report("T4", "object signed by a foreign key rejected",
           not verify(forged, verifier))

    # ---- T5: metadata covert channel ------------------------------------
    print("\nT5  Metadata covert channel (Eq. 5 / Eq. 6)")
    B = int(load_config().integrity["risk_bands"])
    observed = {quantise(r / 1000.0, B)[0] for r in range(1001)}
    report("T5", f"continuous score collapses to exactly {B} bands",
           len(observed) == B, f"observed band indices = {sorted(observed)}")
    bound = channel_capacity_bound(1.0, B)
    report("T5", f"capacity bound at 1 object/s is {bound:.1f} bit/s",
           abs(bound - 2.0) < 1e-9, "C <= lambda * log2(B)")

    print("\n" + "=" * 74)
    ok = all(results)
    print(f"{sum(results)}/{len(results)} checks passed"
          f"{'' if ok else '  <-- REVIEW FAILURES'}")
    print("=" * 74)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
