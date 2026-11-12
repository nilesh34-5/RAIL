"""Hash chain (Eq. 3), Merkle tree and their tamper-evidence."""
from railcds.hashchain import build_hash_chain
from railcds.merkle import merkle_root, merkle_proof, verify_proof
from railcds.models import Chunk
from railcds.session import Session, derive_h0


def _chunks(n, size=64):
    return [Chunk(seq=i, data=bytes([i % 256]) * size) for i in range(n)]


def test_hash_chain_detects_chunk_edit():
    h0 = b"\x00" * 32
    chunks = _chunks(8)
    base = build_hash_chain(chunks, h0)
    # editing one chunk changes its hash and every subsequent hash
    chunks[3] = Chunk(seq=3, data=b"tampered" * 8)
    edited = build_hash_chain(chunks, h0)
    assert base[:3] == edited[:3]
    assert all(base[i] != edited[i] for i in range(3, 8))


def test_hash_chain_detects_reorder():
    h0 = b"\x00" * 32
    chunks = _chunks(4)
    base = merkle_root(build_hash_chain(chunks, h0))
    swapped = [chunks[1], chunks[0], chunks[2], chunks[3]]
    # seq numbers are bound in, so swapping payloads yields a different root
    assert merkle_root(build_hash_chain(swapped, h0)) != base


def test_merkle_proof_roundtrip():
    h0 = b"\x00" * 32
    leaves = build_hash_chain(_chunks(10), h0)
    root = merkle_root(leaves)
    for i in range(len(leaves)):
        proof = merkle_proof(leaves, i)
        assert verify_proof(leaves[i], proof, root)
    # a wrong leaf fails verification
    assert not verify_proof(b"\x11" * 32, merkle_proof(leaves, 0), root)


def test_session_binding_replay():
    s1 = Session.create("policy-A")
    s2 = Session.create("policy-A")
    assert s1.epoch != s2.epoch and s1.h0 != s2.h0        # unique per session
    assert derive_h0(s1.nonce, "policy-A") == s1.h0        # reproducible
    assert derive_h0(s1.nonce, "policy-B") != s1.h0        # policy is bound in
