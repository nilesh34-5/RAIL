"""Risk-adaptive chunking (Eq. 2).

    c(r) = c_max * (c_min / c_max) ** r

At r=0 the object is chunked at c_max (coarse, cheap); at r=1 at c_min (fine,
maximally auditable).  Because the interpolation is geometric the chunk size
falls off proportionally rather than in fixed steps.

RAIL feeds the *quantised* band value r_tilde (not the continuous score) into
this function, so only ``B`` distinct chunk sizes are ever observable from the
receiving side.
"""
from __future__ import annotations

from typing import List

from .models import Chunk


def chunk_size_for_risk(risk: float, c_max: int, c_min: int) -> int:
    """Evaluate c(r) and clamp to the [c_min, c_max] range as an integer."""
    if c_min <= 0 or c_max <= 0 or c_min > c_max:
        raise ValueError("require 0 < c_min <= c_max")
    r = min(max(risk, 0.0), 1.0)
    size = c_max * (c_min / c_max) ** r
    return max(c_min, min(c_max, int(round(size))))


def chunk_object(data: bytes, chunk_size: int) -> List[Chunk]:
    """Split ``data`` into fixed-size chunks (last chunk may be shorter)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    chunks: List[Chunk] = []
    for seq, off in enumerate(range(0, max(len(data), 1), chunk_size)):
        chunks.append(Chunk(seq=seq, data=data[off:off + chunk_size]))
    # an empty object still yields a single empty chunk so a root exists
    if not data:
        chunks = [Chunk(seq=0, data=b"")]
    return chunks
