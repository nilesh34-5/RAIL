"""Protocol / structural validator detector.

A cheap first-line detector that flags structural anomalies which often precede
an exploit attempt: implausible size, control characters where text is expected,
truncated declared containers, or an object whose declared type does not parse.
It is intentionally conservative - it raises modest suspicion rather than
blocking on its own; strong verdicts come from the ML and signature detectors.
"""
from __future__ import annotations

from typing import Any, Dict

from ..models import TransferObject
from .base import Detector

# Well-known container magic -> expected minimum trailer / structure checks
_ZIP_MAGIC = b"PK\x03\x04"
_PDF_MAGIC = b"%PDF-"
_PDF_EOF = b"%%EOF"
_GZIP_MAGIC = b"\x1f\x8b"


class ProtocolValidator(Detector):
    name = "protocol_validator"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.max_bytes = int(cfg.get("max_bytes", 512 * 1024 * 1024))
        super().__init__(weight, cfg, root)

    def score(self, obj: TransferObject) -> tuple[float, str]:
        data = obj.data
        notes = []
        risk = 0.0

        if len(data) == 0:
            return 0.1, "empty object"
        if len(data) > self.max_bytes:
            return 0.7, f"oversized object ({len(data)} bytes)"

        # ZIP/OOXML: must contain the end-of-central-directory marker
        if data.startswith(_ZIP_MAGIC):
            if b"PK\x05\x06" not in data[-65600:]:
                risk = max(risk, 0.6)
                notes.append("zip without end-of-central-directory")

        # PDF: header present but no EOF trailer -> truncated / crafted
        if data.startswith(_PDF_MAGIC):
            if _PDF_EOF not in data[-2048:]:
                risk = max(risk, 0.4)
                notes.append("pdf missing %%EOF trailer")

        # gzip: needs at least the 10-byte header + 8-byte trailer
        if data.startswith(_GZIP_MAGIC) and len(data) < 18:
            risk = max(risk, 0.5)
            notes.append("truncated gzip")

        # a large run of NULs inside a nominally textual object is suspicious
        if obj.meta.get("expected_text") and b"\x00" in data:
            risk = max(risk, 0.5)
            notes.append("NUL bytes in text object")

        return risk, "; ".join(notes) if notes else "structurally plausible"
