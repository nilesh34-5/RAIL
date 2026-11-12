"""Core data structures exchanged between RAIL stages.

These are plain dataclasses with explicit (de)serialisation so that everything
that crosses the one-way link, or is written to an audit log, has a stable,
inspectable wire form.  Bytes are carried as raw bytes in memory and hex/base64
on the wire.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class TransferObject:
    """An application object recovered by Stage S1 (protocol separation)."""

    name: str                       # logical name / relative path
    data: bytes                     # extracted application payload
    src_protocol: str = "file"      # protocol that was terminated (S1)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class DetectorResult:
    """One detector's confidence s_i(O) in [0,1] plus explanatory detail."""

    name: str
    score: float
    weight: float
    detail: str = ""
    available: bool = True


@dataclass
class RiskReport:
    """Aggregate output of Stage S2 (Eq. 1 Noisy-OR and quantisation Eq. 5)."""

    risk: float                      # continuous r(O)
    band: int                        # quantised band index in [0, B-1]
    band_value: float                # r_tilde used downstream
    blocked: bool                    # r >= theta_blk ?
    results: List[DetectorResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Chunk:
    """One adaptive chunk (Stage S3)."""

    seq: int
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)


@dataclass
class Manifest:
    """Everything the receiver needs to reconstruct and verify an object.

    The manifest and the chunk payloads are the only things that cross the
    one-way link.  No transport state and no continuous risk score cross the
    boundary - only the quantised band.
    """

    object_name: str
    object_size: int
    epoch: str                       # session/epoch identifier (nonce-derived)
    policy_id: str                   # policy in force (bound into H0)
    h0: bytes                        # session-bound initial hash
    band: int                        # quantised risk band
    chunk_count: int
    chunk_lengths: List[int]
    merkle_root: bytes
    signature: bytes                 # Ed25519 over (root||epoch||band||policy)
    hash_algo: str = "sha256"

    # ---- serialisation ----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_name": self.object_name,
            "object_size": self.object_size,
            "epoch": self.epoch,
            "policy_id": self.policy_id,
            "h0": _b64e(self.h0),
            "band": self.band,
            "chunk_count": self.chunk_count,
            "chunk_lengths": self.chunk_lengths,
            "merkle_root": _b64e(self.merkle_root),
            "signature": _b64e(self.signature),
            "hash_algo": self.hash_algo,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Manifest":
        return cls(
            object_name=d["object_name"],
            object_size=d["object_size"],
            epoch=d["epoch"],
            policy_id=d["policy_id"],
            h0=_b64d(d["h0"]),
            band=d["band"],
            chunk_count=d["chunk_count"],
            chunk_lengths=list(d["chunk_lengths"]),
            merkle_root=_b64d(d["merkle_root"]),
            signature=_b64d(d["signature"]),
            hash_algo=d.get("hash_algo", "sha256"),
        )

    def signing_payload(self) -> bytes:
        """Bytes that the Ed25519 signature covers (Stage S3 sign / S5 verify)."""
        return (
            self.merkle_root
            + self.epoch.encode("utf-8")
            + self.band.to_bytes(4, "big")
            + self.policy_id.encode("utf-8")
        )


@dataclass
class AuditEntry:
    """One append-only audit-log record (identical schema on both sides)."""

    ts: float
    epoch: str
    object_name: str
    object_size: int
    band: int
    merkle_root: str          # hex
    signature: str            # base64
    side: str                 # "sender" | "receiver"
    verified: Optional[bool] = None   # receiver-side verification outcome

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
