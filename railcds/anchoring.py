"""Risk-adaptive ledger anchoring (Eq. 4).

    T(r) = T_min + (T_max - T_min) * (1 - r) ** gamma

Anchoring the Merkle root to an external ledger gives non-repudiation, but doing
so per object does not scale (the paper cites Hyperledger Fabric throughput).
RAIL anchors only the Merkle root and only periodically; one root already commits
to every chunk, so anchoring at intervals preserves tamper evidence for
everything in between.  The interval itself is risk-adaptive: higher risk
shortens it (more frequent anchoring), the inverse of the chunk-size relation.

The ledger is abstracted: a ``file`` backend appends to a local JSON-lines
"ledger" (sufficient to demonstrate and audit), and an ``http`` backend POSTs to
a REST endpoint (e.g., a permissioned-ledger gateway).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


def anchoring_interval(risk: float, t_min: float, t_max: float, gamma: float) -> float:
    """Evaluate T(r) in seconds (Eq. 4)."""
    r = min(max(risk, 0.0), 1.0)
    return t_min + (t_max - t_min) * (1.0 - r) ** gamma


class Ledger:
    """Minimal ledger sink (file or http)."""

    def __init__(self, backend: str, path: Optional[Path] = None,
                 endpoint: Optional[str] = None) -> None:
        self.backend = backend
        self.path = Path(path) if path else None
        self.endpoint = endpoint
        if self.backend == "file" and self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def anchor(self, record: dict) -> None:
        record = {**record, "anchored_at": time.time()}
        if self.backend == "file":
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        elif self.backend == "http":
            import urllib.request
            data = json.dumps(record).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint, data=data,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            urllib.request.urlopen(req, timeout=10).read()
        else:
            raise ValueError(f"unknown ledger backend: {self.backend}")


class AnchorManager:
    """Decides when to anchor based on the risk-adaptive interval T(r)."""

    def __init__(self, cfg: dict, ledger: Ledger) -> None:
        self.t_min = float(cfg["t_min_seconds"])
        self.t_max = float(cfg["t_max_seconds"])
        self.gamma = float(cfg["gamma"])
        self.ledger = ledger
        self._last_anchor = 0.0     # forces an anchor on the first object

    def interval_for(self, risk: float) -> float:
        return anchoring_interval(risk, self.t_min, self.t_max, self.gamma)

    def maybe_anchor(self, risk: float, record: dict, now: Optional[float] = None) -> bool:
        """Anchor ``record`` if T(risk) has elapsed since the last anchor."""
        now = time.time() if now is None else now
        if now - self._last_anchor >= self.interval_for(risk):
            self.ledger.anchor(record)
            self._last_anchor = now
            return True
        return False
