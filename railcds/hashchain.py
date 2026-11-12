"""Linked hash chain - the first half of the Merkle input (Eq. 3).

    H_i = SHA-256( H_{i-1} || seq_i || len_i || m_i )

Every chunk hash folds in the previous hash (chain), its sequence number
(defeats reordering/replay), its length (fixes chunk boundaries) and its payload
(covers content).  ``seq`` and ``len`` are encoded as fixed-width big-endian
integers so the concatenation is unambiguous.
"""
from __future__ import annotations

from typing import List

from .crypto import sha256
from .models import Chunk

SEQ_BYTES = 8   # 64-bit sequence number
LEN_BYTES = 8   # 64-bit length in bytes


def chunk_hash(prev: bytes, seq: int, length: int, payload: bytes) -> bytes:
    """Compute a single H_i per Eq. (3)."""
    return sha256(
        prev,
        seq.to_bytes(SEQ_BYTES, "big"),
        length.to_bytes(LEN_BYTES, "big"),
        payload,
    )


def build_hash_chain(chunks: List[Chunk], h0: bytes) -> List[bytes]:
    """Return the list ``[H_1, H_2, ... H_n]`` starting from the session H0.

    The returned per-chunk hashes are the leaves handed to the Merkle tree.
    """
    hashes: List[bytes] = []
    prev = h0
    for c in chunks:
        h = chunk_hash(prev, c.seq, c.length, c.data)
        hashes.append(h)
        prev = h
    return hashes
