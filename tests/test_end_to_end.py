"""Full integrity path S3->S4->S4'->S5 with FEC loss and tamper detection.

Exercises the cryptographic pipeline directly (no sockets, config or ML models)
so it runs anywhere: chunk -> hash chain -> Merkle root -> sign -> pack -> FEC
-> lossy channel -> FEC decode -> unpack -> recompute -> verify.
"""
import os
import random

from railcds.chunker import chunk_object, chunk_size_for_risk
from railcds.crypto import generate_keypair, Signer, Verifier
from railcds.fec import FEC, FecDecoder
from railcds.hashchain import build_hash_chain
from railcds.merkle import merkle_root
from railcds.models import Manifest
from railcds.session import Session
from railcds import wire


def _build_payload(data: bytes, band: int, bands: int, signer: Signer):
    session = Session.create("policy-test")
    band_value = band / bands
    size = chunk_size_for_risk(band_value, 1_048_576, 16_384)
    chunks = chunk_object(data, size)
    leaves = build_hash_chain(chunks, session.h0)
    root = merkle_root(leaves)
    m = Manifest(
        object_name="obj.bin", object_size=len(data), epoch=session.epoch,
        policy_id="policy-test", h0=session.h0, band=band,
        chunk_count=len(chunks), chunk_lengths=[c.length for c in chunks],
        merkle_root=root, signature=b"",
    )
    m.signature = signer.sign(m.signing_payload())
    return wire.pack_object(m, data)


def _receive(payload: bytes, verifier: Verifier):
    manifest, chunks = wire.unpack_object(payload)
    leaves = build_hash_chain(chunks, manifest.h0)
    root = merkle_root(leaves)
    root_ok = root == manifest.merkle_root
    sig_ok = verifier.verify(manifest.signature, manifest.signing_payload())
    data = b"".join(c.data for c in chunks)
    return root_ok and sig_ok, data


def test_end_to_end_with_loss():
    random.seed(3)
    priv, pub = generate_keypair()
    signer, verifier = Signer(priv), Verifier(pub)
    data = os.urandom(120_000)
    payload = _build_payload(data, band=2, bands=4, signer=signer)

    fec = FEC(backend="reedsolo", symbol_size=1024, overhead=0.4)
    syms = fec.encode(payload, obj_id=1)
    kept = [s for s in syms if random.random() > 0.2]
    random.shuffle(kept)
    dec = FecDecoder()
    done = None
    for s in kept:
        r = dec.add(s)
        if r is not None:
            done = r
    assert done == 1
    ok, recovered = _receive(dec.reconstruct(1), verifier)
    assert ok and recovered == data


def test_tamper_is_rejected():
    priv, pub = generate_keypair()
    signer, verifier = Signer(priv), Verifier(pub)
    data = bytearray(os.urandom(50_000))
    payload = bytearray(_build_payload(bytes(data), band=1, bands=4, signer=signer))
    # flip a byte in the object region (after the manifest) -> root mismatch
    payload[-100] ^= 0xFF
    ok, _ = _receive(bytes(payload), verifier)
    assert ok is False


def test_wrong_key_is_rejected():
    priv, pub = generate_keypair()
    _, other_pub = generate_keypair()
    signer, wrong_verifier = Signer(priv), Verifier(other_pub)
    data = os.urandom(10_000)
    payload = _build_payload(data, band=0, bands=4, signer=signer)
    ok, _ = _receive(payload, wrong_verifier)
    assert ok is False
