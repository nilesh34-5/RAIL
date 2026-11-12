"""Session binding - deriving the initial hash H0 (Sec. "Session Binding").

The linked hash chain (Eq. 3) needs a starting value H0.  A fixed constant would
make every session's chain start identically and let a captured object be
replayed.  RAIL instead derives H0 from a per-session nonce (never reused) and
the identifier of the security policy in force:

    epoch = base64(nonce)
    H0    = SHA-256( b"RAIL-H0" || nonce || policy_id )

* The nonce makes each chain unique and defeats replay (the receiver recomputes
  from its own copy of H0, carried in the manifest, and a replayed object under a
  new epoch will not match).
* The policy_id records which inspection configuration was active, so a chain
  verified months later can be checked against the rules that applied then.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from .crypto import sha256

DOMAIN = b"RAIL-H0"
NONCE_BYTES = 16


@dataclass
class Session:
    """A single transfer session: its epoch id, nonce, policy and H0."""

    epoch: str
    nonce: bytes
    policy_id: str
    h0: bytes

    @classmethod
    def create(cls, policy_id: str) -> "Session":
        nonce = os.urandom(NONCE_BYTES)
        epoch = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
        h0 = sha256(DOMAIN, nonce, policy_id.encode("utf-8"))
        return cls(epoch=epoch, nonce=nonce, policy_id=policy_id, h0=h0)


def derive_h0(nonce: bytes, policy_id: str) -> bytes:
    """Recompute H0 from a nonce and policy id (used to cross-check a manifest)."""
    return sha256(DOMAIN, nonce, policy_id.encode("utf-8"))
