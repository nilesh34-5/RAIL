"""Binary Merkle tree over the chunk hashes (Stage S3).

The root is the object's integrity commitment: a single 32-byte value that
depends on every chunk.  Proof size grows logarithmically with the chunk count,
which is why the paper prefers a tree to a flat signed list.

Construction rules (kept simple and standard):
* Leaves are the per-chunk hashes H_i from the linked hash chain.
* Interior node = SHA-256(left || right).
* If a level has an odd number of nodes the last node is duplicated (promoted).
* An empty object commits to SHA-256(b"") so the root is always defined.

Domain separation (0x00 leaf / 0x01 interior prefixes) is applied to prevent
second-preimage collisions between leaves and interior nodes.
"""
from __future__ import annotations

from typing import List, Tuple

from .crypto import sha256

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _leaf(h: bytes) -> bytes:
    return sha256(LEAF_PREFIX, h)


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX, left, right)


def merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """Return the Merkle root over the supplied leaf hashes."""
    if not leaf_hashes:
        return sha256(b"")
    level = [_leaf(h) for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])          # promote the odd tail
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaf_hashes: List[bytes], index: int) -> List[Tuple[bytes, str]]:
    """Return an inclusion proof for ``index`` as [(sibling, 'L'|'R'), ...].

    Included so a single chunk can be proven a member of the committed object
    without shipping the whole log - the property the paper highlights.
    """
    if not leaf_hashes:
        raise ValueError("empty tree has no proofs")
    level = [_leaf(h) for h in leaf_hashes]
    idx = index
    proof: List[Tuple[bytes, str]] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            proof.append((level[idx + 1], "R"))
        else:
            proof.append((level[idx - 1], "L"))
        idx //= 2
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


def verify_proof(leaf_hash: bytes, proof: List[Tuple[bytes, str]], root: bytes) -> bool:
    """Verify an inclusion proof produced by :func:`merkle_proof`."""
    acc = _leaf(leaf_hash)
    for sibling, side in proof:
        acc = _node(sibling, acc) if side == "L" else _node(acc, sibling)
    return acc == root
