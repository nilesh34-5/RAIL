"""GF(256) field correctness and FEC erasure round-trips under loss."""
import os
import random

from railcds import gf256
from railcds.fec import FEC, FecDecoder


def test_field_inverse_and_mul():
    # every nonzero element has a multiplicative inverse; a * inv(a) == 1
    for a in range(1, 256):
        assert gf256.mul(a, gf256.inv(a)) == 1
    # multiplication is commutative and 1 is the identity
    for _ in range(200):
        a, b = random.randint(0, 255), random.randint(0, 255)
        assert gf256.mul(a, b) == gf256.mul(b, a)
        assert gf256.mul(a, 1) == a


def test_generator_is_primitive():
    # base-3 generator must hit all 255 nonzero elements exactly once
    seen = {int(gf256._EXP[i]) for i in range(255)}
    assert len(seen) == 255 and 0 not in seen


def test_fec_roundtrip_no_loss():
    for size in (0, 1, 1000, 1024, 200_000):
        payload = os.urandom(size)
        fec = FEC(backend="reedsolo", symbol_size=1024)
        syms = fec.encode(payload, obj_id=1)
        dec = FecDecoder()
        done = None
        for s in syms:
            r = dec.add(s)
            if r is not None:
                done = r
        assert done == 1
        assert dec.reconstruct(1) == payload


def test_fec_recovers_under_loss():
    random.seed(7)
    payload = os.urandom(150_000)                          # spans 2 generations
    # overhead must exceed the loss rate with margin for per-generation variance
    fec = FEC(backend="reedsolo", symbol_size=1024, overhead=0.6)
    syms = fec.encode(payload, obj_id=2)
    kept = [s for s in syms if random.random() > 0.2]      # 20% loss
    random.shuffle(kept)
    dec = FecDecoder()
    done = None
    for s in kept:
        r = dec.add(s)
        if r is not None:
            done = r
    assert done == 2
    assert dec.reconstruct(2) == payload


def test_fec_ignores_redundant_symbols():
    payload = b"hello world"
    fec = FEC(backend="reedsolo", symbol_size=1024)
    syms = fec.encode(payload, obj_id=3)
    dec = FecDecoder()
    completions = [dec.add(s) for s in syms]
    dec.reconstruct(3)
    # feeding the same symbols again must not re-complete the object
    assert all(dec.add(s) is None for s in syms)


def test_decoder_ignores_malformed_headers():
    """A gateway must not crash on what arrives over a one-way link.

    Regression: a RaptorQ symbol (k=0) reaching a decoder built for the block
    code was parsed as Reed-Solomon and crashed the receiver with
    'need at least one array to concatenate'.
    """
    from railcds.fec import HEADER, MAGIC, VERSION
    dec = FecDecoder()
    bad = [
        HEADER.pack(MAGIC, VERSION, 1, 0, 1, 0, 0, 0, 1024, 100),   # k=0
        HEADER.pack(MAGIC, VERSION, 2, 0, 1, 0, 5, 2, 1024, 100),   # n < k
        HEADER.pack(MAGIC, VERSION, 3, 0, 1, 0, 4, 8, 0, 100),      # block=0
        HEADER.pack(MAGIC, VERSION, 4, 9, 1, 0, 4, 8, 1024, 100),   # gid>=count
        b"NOTRAIL" + b"\x00" * 40,                                   # bad magic
        b"",                                                          # empty
    ]
    for d in bad:
        assert dec.add(d + b"\x00" * 1024) is None


def test_reconstruct_raises_not_crashes_when_incomplete():
    payload = os.urandom(50_000)
    fec = FEC(backend="reedsolo", symbol_size=1024, overhead=0.5)
    syms = fec.encode(payload, obj_id=9)
    dec = FecDecoder()
    for s in syms[:2]:          # far too few to invert
        dec.add(s)
    try:
        dec.reconstruct(9)
    except ValueError:
        pass                     # a clean, catchable error is the contract
    else:
        raise AssertionError("expected ValueError for an incomplete object")
