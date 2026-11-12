"""Offline YARA signature detector.

Compiles every ``*.yar`` / ``*.yara`` rule found under the configured rules
directory (populated by ``scripts/download_models.py``) and scans each object.
A match raises the confidence; the confidence scales with the number and
declared severity of matching rules.  A rule may set ``meta: severity = "high"``
to weight its contribution.

If no rules are present the detector reports itself unavailable (weight has no
effect) rather than silently returning 0 for every object.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

from ..models import TransferObject
from .base import Detector

try:
    import yara
    _HAVE_YARA = True
except Exception:      # noqa: BLE001
    _HAVE_YARA = False

_SEVERITY = {"info": 0.15, "low": 0.4, "medium": 0.7,
             "high": 0.95, "critical": 1.0}


class YaraSignatureDetector(Detector):
    name = "yara_signature"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.rules_dir = cfg.get("rules_dir", "models/yara")
        self._rules = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        if not _HAVE_YARA:
            raise RuntimeError("yara-python not installed")
        rd = Path(self.rules_dir)
        if not rd.is_absolute():
            rd = self.root / rd
        files = sorted(
            [p for p in rd.rglob("*") if p.suffix.lower() in (".yar", ".yara")]
        ) if rd.exists() else []
        if not files:
            raise RuntimeError(f"no YARA rules under {rd}")
        # compile with namespaced sources; skip individual files that fail
        sources: Dict[str, str] = {}
        for i, f in enumerate(files):
            try:
                sources[f"ns{i}"] = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:      # noqa: BLE001
                continue
        # compile each namespace independently so one bad file cannot void all
        compiled = {}
        for ns, src in sources.items():
            try:
                compiled[ns] = yara.compile(source=src)
            except yara.Error:
                continue
        if not compiled:
            raise RuntimeError("no YARA rules compiled successfully")
        self._rules = compiled
        self._rule_count = len(compiled)

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        best = 0.0
        hits = []
        for ns, rules in self._rules.items():
            try:
                matches = rules.match(data=obj.data, timeout=10)
            except yara.Error as exc:
                continue
            for m in matches:
                sev = str(m.meta.get("severity", "medium")).lower()
                best = max(best, _SEVERITY.get(sev, 0.7))
                hits.append(m.rule)
        if not hits:
            return 0.0, f"no match ({self._rule_count} rule sets)"
        return best, f"YARA match: {', '.join(hits[:5])}"
