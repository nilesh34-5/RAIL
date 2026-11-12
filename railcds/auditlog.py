"""Append-only, tamper-evident audit log (Sec. "Append Only Audit Log").

Both gateways keep their own log, written independently.  Each record holds the
Merkle root, the signature over it, the quantised risk band, the epoch id and a
timestamp.  Records are additionally chained: every entry stores the SHA-256 of
the previous entry, so altering or deleting a historical record breaks the chain
and surfaces on verification.  The two logs, anchored separately, can be compared
during a later audit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from .crypto import sha256

GENESIS = b"\x00" * 32


class AuditLog:
    """A single side's append-only log backed by a JSON-lines file."""

    def __init__(self, path: Path, side: str) -> None:
        self.path = Path(path)
        self.side = side
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> bytes:
        if not self.path.exists():
            return GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS
        return sha256(last.encode("utf-8"))

    def append(self, entry: dict) -> str:
        """Append an entry (dict); returns the new chain head as hex."""
        record = dict(entry)
        record["prev"] = self._last_hash.hex()
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._last_hash = sha256(line.encode("utf-8"))
        return self._last_hash.hex()

    def entries(self) -> List[dict]:
        out = []
        if not self.path.exists():
            return out
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify_chain(self) -> Optional[int]:
        """Return None if the chain is intact, else the 0-based broken index."""
        prev = GENESIS.hex()
        with open(self.path, "r", encoding="utf-8") as fh:
            idx = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("prev") != prev:
                    return idx
                prev = sha256(line.encode("utf-8")).hex()
                idx += 1
        return None
