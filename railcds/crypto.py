"""Cryptographic primitives for RAIL.

* SHA-256 hashing (used by the hash chain, Eq. 3, and the Merkle tree).
* Ed25519 signatures over Merkle roots (Bernstein et al., cited in the paper).

The sender holds the private key and signs each object's Merkle root together
with the epoch, quantised band and policy id.  The receiver holds only the
public key and verifies at Stage S5.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def sha256(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of ``parts`` (256-bit digest)."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


# ---------------------------------------------------------------------------
# Ed25519 key management
# ---------------------------------------------------------------------------
def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_raw, public_raw)`` as raw 32-byte encodings."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def save_keypair(priv: bytes, pub: bytes, priv_path: Path, pub_path: Path) -> None:
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv)
    pub_path.write_bytes(pub)
    try:  # best-effort tighten perms on POSIX; no-op on Windows
        priv_path.chmod(0o600)
    except (PermissionError, NotImplementedError):
        pass


class Signer:
    """Sender-side signer holding the Ed25519 private key."""

    def __init__(self, private_raw: bytes) -> None:
        self._sk = Ed25519PrivateKey.from_private_bytes(private_raw)

    @classmethod
    def from_file(cls, path: Path) -> "Signer":
        p = Path(path)
        if not p.exists():
            # A missing private key means one of two very different things, and
            # a bare FileNotFoundError tells the operator neither of them.
            raise FileNotFoundError(
                f"Sender private key not found: {p}\n"
                f"  If this is the SENDER (Network A), create the keypair:\n"
                f"      ./rail keys\n"
                f"  then copy ONLY data/keys/sender_ed25519.pub to the receiver.\n"
                f"  If this is the RECEIVER (Network B), this is CORRECT - it must\n"
                f"  never hold the private key. Sender-side commands (send,\n"
                f"  demo_local.py, demo_attacks.py) cannot run on the receiver."
            )
        return cls(p.read_bytes())

    def sign(self, payload: bytes) -> bytes:
        return self._sk.sign(payload)


class Verifier:
    """Receiver-side verifier holding only the Ed25519 public key."""

    def __init__(self, public_raw: bytes) -> None:
        self._pk = Ed25519PublicKey.from_public_bytes(public_raw)

    @classmethod
    def from_file(cls, path: Path) -> "Verifier":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Sender public key not found: {p}\n"
                f"  Copy it from the sender:  data/keys/sender_ed25519.pub\n"
                f"  Without it the receiver cannot verify any signature and\n"
                f"  every object would be rejected."
            )
        return cls(p.read_bytes())

    def verify(self, signature: bytes, payload: bytes) -> bool:
        try:
            self._pk.verify(signature, payload)
            return True
        except InvalidSignature:
            return False
