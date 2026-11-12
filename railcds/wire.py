"""Serialisation of a transfer across the one-way link.

A single object's on-wire payload is::

    [ 4 bytes: manifest JSON length ][ manifest JSON ][ object bytes ]

The manifest carries the chunk lengths, so the receiver re-splits the trailing
object bytes into the exact same chunks the sender hashed.  Only this payload
(after FEC encoding) and nothing else crosses the boundary: no transport state,
no continuous risk score - only the quantised band recorded in the manifest.
"""
from __future__ import annotations

import json
import struct
from typing import List, Tuple

from .models import Chunk, Manifest

_LEN = struct.Struct(">I")


def pack_object(manifest: Manifest, object_bytes: bytes) -> bytes:
    mjson = json.dumps(manifest.to_dict(), separators=(",", ":")).encode("utf-8")
    return _LEN.pack(len(mjson)) + mjson + object_bytes


def unpack_object(payload: bytes) -> Tuple[Manifest, List[Chunk]]:
    (mlen,) = _LEN.unpack(payload[:4])
    off = 4
    manifest = Manifest.from_dict(json.loads(payload[off:off + mlen].decode("utf-8")))
    off += mlen
    obj = payload[off:off + manifest.object_size]
    # re-split into the sender's chunks using the manifest's chunk_lengths
    chunks: List[Chunk] = []
    pos = 0
    for seq, length in enumerate(manifest.chunk_lengths):
        chunks.append(Chunk(seq=seq, data=obj[pos:pos + length]))
        pos += length
    return manifest, chunks
