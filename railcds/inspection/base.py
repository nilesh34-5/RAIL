"""Detector base class for Stage S2.

A detector receives a :class:`TransferObject` and returns a confidence in [0,1]
that the object is dangerous.  Detectors must be independent (the Noisy-OR model
assumes conditional independence) and must fail safe: any internal error is
reported as ``available=False`` with score 0.0 rather than crashing the pipeline
(a detector outage must never silently lower an object's risk in a way that
hides it - the operator sees the detector went unavailable in the report).
"""
from __future__ import annotations

import abc
from typing import Any, Dict

from ..models import DetectorResult, TransferObject


class Detector(abc.ABC):
    """Abstract independent detector producing s_i(O)."""

    #: stable identifier matching the key under inspection.detectors in the YAML
    name: str = "detector"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.weight = float(weight)
        self.cfg = cfg
        self.root = root          # project root Path for resolving model files
        self._available = True
        self._load_error = ""
        try:
            self.setup()
        except Exception as exc:   # noqa: BLE001 - detectors must fail safe
            self._available = False
            self._load_error = f"{type(exc).__name__}: {exc}"

    # -- lifecycle ----------------------------------------------------------
    def setup(self) -> None:
        """Load models / rules.  Override in subclasses; may raise on failure."""

    @abc.abstractmethod
    def score(self, obj: TransferObject) -> tuple[float, str]:
        """Return ``(confidence, human_detail)``; confidence in [0,1]."""

    # -- driver -------------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._available

    def evaluate(self, obj: TransferObject) -> DetectorResult:
        if not self._available:
            return DetectorResult(
                name=self.name, score=0.0, weight=self.weight,
                detail=f"unavailable ({self._load_error})", available=False,
            )
        try:
            s, detail = self.score(obj)
            s = min(max(float(s), 0.0), 1.0)
            return DetectorResult(self.name, s, self.weight, detail, True)
        except Exception as exc:   # noqa: BLE001
            return DetectorResult(
                name=self.name, score=0.0, weight=self.weight,
                detail=f"error: {type(exc).__name__}: {exc}", available=False,
            )
