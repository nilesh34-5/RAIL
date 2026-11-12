"""Forward error correction for the one-way channel (Stage S4 / S4').

Because a strict data diode has no back channel, reliable delivery must be
achieved without retransmission requests.  This module encodes a payload into
``n`` coded symbols such that the receiver can reconstruct it from *any* ``k`` of
them - so loss is a matter of sending somewhat more data rather than an
unrecoverable failure (the fountain-code property discussed in the paper).

Backends (selected by config ``fec.backend``):
  * ``raptorq``  - RFC 6330 fountain code, used automatically if the optional
                   ``raptorq`` package is importable.
  * ``reedsolo`` - portable systematic Cauchy Reed-Solomon MDS erasure code
                   built on :mod:`gf256` (default; no native deps).
  * ``repetition`` - blind repetition, the simplest option in the paper's table.

Large payloads are split into fixed-size *generations* so every symbol fits in
one datagram; each symbol is self-describing (its header carries obj id,
generation id/count, encoding-symbol id and coding parameters).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from math import ceil
from typing import Dict, List, Optional, Tuple

import numpy as np

from . import gf256

MAGIC = b"RQ"
VERSION = 1
# ">2s B I H H H H H I I" -> magic,ver,obj_id,gen_id,gen_count,esi,k,n,block,gen_len
HEADER = struct.Struct(">2sBIHHHHHII")
HEADER_SIZE = HEADER.size  # 25

K_MAX = 128  # source symbols per generation (keeps n = ceil(1.35k) <= 256)


def _have_raptorq() -> bool:
    try:
        import raptorq  # noqa: F401
        return True
    except Exception:      # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Systematic Cauchy Reed-Solomon erasure code
# ---------------------------------------------------------------------------
def _generator(k: int, n: int) -> np.ndarray:
    """(n x k) generator: identity on top (systematic) + Cauchy repair rows."""
    g = np.zeros((n, k), dtype=np.uint8)
    g[:k, :k] = np.eye(k, dtype=np.uint8)
    if n > k:
        g[k:, :] = gf256.cauchy_matrix(n - k, k)
    return g


@dataclass
class FEC:
    backend: str = "auto"
    symbol_size: int = 1024
    overhead: float = 0.35
    repeat: int = 1

    _effective: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if self.backend == "auto":
            self._effective = "raptorq" if _have_raptorq() else "reedsolo"
        else:
            self._effective = self.backend

    @property
    def effective_backend(self) -> str:
        return self._effective

    # -- encoding -----------------------------------------------------------
    def encode(self, payload: bytes, obj_id: int) -> List[bytes]:
        """Return a list of datagram-ready coded symbols for ``payload``."""
        if self._effective == "raptorq":
            symbols = self._encode_raptorq(payload, obj_id)
            if self.repeat > 1:
                symbols = [s for s in symbols for _ in range(self.repeat)]
            return symbols

        block = self.symbol_size
        gen_bytes = K_MAX * block
        generations = [payload[i:i + gen_bytes] for i in range(0, max(len(payload), 1), gen_bytes)]
        gen_count = len(generations)
        symbols: List[bytes] = []
        for gid, gen in enumerate(generations):
            symbols.extend(self._encode_generation(gen, obj_id, gid, gen_count, block))
        if self.repeat > 1:
            symbols = [s for s in symbols for _ in range(self.repeat)]
        return symbols

    def _encode_raptorq(self, payload: bytes, obj_id: int) -> List[bytes]:
        """RFC 6330 fountain encoding (RaptorQ).

        Unlike the block code, RaptorQ needs no generation splitting: the
        library emits self-identifying MTU-sized packets for the whole object
        and the receiver recovers once it holds roughly as many packets as the
        object had source symbols, regardless of *which* ones arrived.

        ``k = 0`` in the RAIL header marks a RaptorQ symbol. The block code
        always uses k >= 1, so the sentinel is unambiguous.
        """
        import raptorq

        block = self.symbol_size
        if not payload:
            # nothing to encode; a single header carries the empty object
            return [HEADER.pack(MAGIC, VERSION, obj_id, 0, 1, 0, 0, 0, block, 0)]

        enc = raptorq.Encoder.with_defaults(payload, block)
        source = max(1, ceil(len(payload) / block))
        repair = max(1, int(round(source * self.overhead)))
        packets = enc.get_encoded_packets(repair)

        out = []
        for i, pkt in enumerate(packets):
            hdr = HEADER.pack(MAGIC, VERSION, obj_id, 0, 1,
                              min(i, 0xFFFF), 0, 0, block, len(payload))
            out.append(hdr + pkt)
        return out

    def _encode_generation(self, gen: bytes, obj_id: int, gid: int,
                           gen_count: int, block: int) -> List[bytes]:
        gen_len = len(gen)
        k = max(1, min(K_MAX, ceil(gen_len / block) if gen_len else 1))
        padded = gen + b"\x00" * (k * block - gen_len)
        D = np.frombuffer(padded, dtype=np.uint8).reshape(k, block)

        if self._effective == "repetition":
            # send each source block once; reliability comes from self.repeat
            n = k
            coded = D
        else:  # reedsolo: systematic Cauchy Reed-Solomon block code
            n = min(256, max(k + 1, ceil(k * (1.0 + self.overhead))))
            G = _generator(k, n)
            coded = gf256.matmul(G, D)

        out = []
        for esi in range(n):
            hdr = HEADER.pack(MAGIC, VERSION, obj_id, gid, gen_count,
                              esi, k, n, block, gen_len)
            out.append(hdr + coded[esi].tobytes())
        return out


# ---------------------------------------------------------------------------
# Decoder / collector
# ---------------------------------------------------------------------------
@dataclass
class _GenState:
    k: int
    n: int
    block: int
    gen_len: int
    symbols: Dict[int, np.ndarray] = field(default_factory=dict)

    def complete(self) -> bool:
        return len(self.symbols) >= self.k


@dataclass
class _ObjState:
    gen_count: int
    gens: Dict[int, _GenState] = field(default_factory=dict)

    def complete(self) -> bool:
        return (len(self.gens) == self.gen_count
                and all(g.complete() for g in self.gens.values()))


class FecDecoder:
    """Accumulates coded symbols and reconstructs whole objects."""

    def __init__(self) -> None:
        self._objs: Dict[int, _ObjState] = {}
        self._done: set[int] = set()   # obj_ids already reconstructed
        self._rq: Dict[int, dict] = {}  # per-object RaptorQ decoder state

    def add(self, datagram: bytes) -> Optional[int]:
        """Ingest one datagram; return an obj_id if that object is now complete."""
        if len(datagram) < HEADER_SIZE:
            return None
        magic, ver, obj_id, gid, gen_count, esi, k, n, block, gen_len = \
            HEADER.unpack(datagram[:HEADER_SIZE])
        if magic != MAGIC or ver != VERSION:
            return None
        if obj_id in self._done:       # ignore redundant symbols for a finished object
            return None

        # k == 0 marks a RaptorQ symbol (the block code always uses k >= 1).
        if k == 0:
            try:
                return self._add_raptorq(obj_id, block, gen_len,
                                         datagram[HEADER_SIZE:])
            except ImportError:
                # The sender chose RaptorQ but this gateway cannot decode it.
                # Drop the symbol rather than fail: a receiver must never crash
                # on what arrives over the one-way link, since it cannot ask for
                # anything different. Pin fec.backend explicitly on both sides.
                return None

        # Defensive: ignore structurally impossible headers instead of trusting
        # them. Everything here arrives from the network and cannot be queried.
        if k < 1 or n < k or block < 1 or gen_count < 1 or gid >= gen_count:
            return None
        body = datagram[HEADER_SIZE:HEADER_SIZE + block]
        if len(body) < block:
            body = body + b"\x00" * (block - len(body))
        obj = self._objs.setdefault(obj_id, _ObjState(gen_count=gen_count))
        gen = obj.gens.setdefault(gid, _GenState(k=k, n=n, block=block, gen_len=gen_len))
        if esi not in gen.symbols:
            gen.symbols[esi] = np.frombuffer(body, dtype=np.uint8)
        return obj_id if obj.complete() else None

    def _add_raptorq(self, obj_id: int, block: int, gen_len: int,
                     packet: bytes) -> Optional[int]:
        """Feed one RaptorQ packet; return obj_id once the object decodes."""
        st = self._rq.get(obj_id)
        if st is None:
            if gen_len == 0:                       # empty object, nothing to decode
                self._rq[obj_id] = {"data": b"", "done": True}
                return obj_id
            import raptorq
            st = {"dec": raptorq.Decoder.with_defaults(gen_len, block),
                  "done": False, "data": None}
            self._rq[obj_id] = st
        if st["done"]:
            return None
        result = st["dec"].decode(packet)
        if result is None:
            return None
        st["data"] = bytes(result)
        st["done"] = True
        return obj_id

    def reconstruct(self, obj_id: int) -> bytes:
        """Reconstruct a completed object's payload; raises if not complete."""
        if obj_id in self._rq:
            st = self._rq[obj_id]
            if not st["done"]:
                raise ValueError(f"object {obj_id} not yet complete")
            return st["data"]
        obj = self._objs[obj_id]
        if not obj.complete():
            raise ValueError(f"object {obj_id} not yet complete")
        parts = []
        for gid in range(obj.gen_count):
            parts.append(self._reconstruct_generation(obj.gens[gid]))
        self._done.add(obj_id)          # reconstruction is terminal for this obj
        return b"".join(parts)

    @staticmethod
    def _reconstruct_generation(gen: _GenState) -> bytes:
        k, n, block = gen.k, gen.n, gen.block
        if k < 1 or len(gen.symbols) < k:
            raise ValueError(
                f"generation not recoverable: k={k}, have {len(gen.symbols)} symbols")
        have = sorted(gen.symbols.keys())[:k]
        # systematic fast path: if all k source symbols (esi < k) are present
        if all(e < k for e in have) and len(have) == k and set(have) == set(range(k)):
            D = np.vstack([gen.symbols[e] for e in range(k)])
        else:
            G = _generator(k, n)
            rows = have
            Gsub = G[rows, :]
            Ginv = gf256.mat_inv(Gsub)
            C = np.vstack([gen.symbols[e] for e in rows])
            D = gf256.matmul(Ginv, C)
        flat = D.reshape(-1).tobytes()
        return flat[:gen.gen_len]

    def drop(self, obj_id: int) -> None:
        self._objs.pop(obj_id, None)
        self._rq.pop(obj_id, None)
        self._done.add(obj_id)


def make_fec(cfg: dict) -> FEC:
    return FEC(
        backend=cfg.get("backend", "auto"),
        symbol_size=int(cfg.get("symbol_size", 1024)),
        overhead=float(cfg.get("overhead", 0.35)),
        repeat=int(cfg.get("repeat", 1)),
    )
