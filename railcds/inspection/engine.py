"""Stage S2 orchestration: run all configured detectors and aggregate.

Loads the detectors named in ``inspection.detectors``, runs each against the
object, combines their weighted confidences with Noisy-OR (Eq. 1), applies the
block threshold theta_blk, and quantises the score to a band (Eq. 5).
"""
from __future__ import annotations

from typing import Dict, List, Type

from ..config import Config
from ..models import RiskReport, TransferObject
from ..quantize import quantise
from ..risk import noisy_or
from .base import Detector

# Detector registry -----------------------------------------------------------
from .protocol_validator import ProtocolValidator
from .filetype import FileTypeDetector
from .entropy_anomaly import EntropyAnomalyDetector
from .yara_signature import YaraSignatureDetector
from .ember_ml import EmberMalwareDetector
from .ember2024_ml import Ember2024Detector
from .malconv_ml import MalConvDetector
from .malconvgct_ml import MalConvGCTDetector

REGISTRY: Dict[str, Type[Detector]] = {
    ProtocolValidator.name: ProtocolValidator,
    FileTypeDetector.name: FileTypeDetector,
    EntropyAnomalyDetector.name: EntropyAnomalyDetector,
    YaraSignatureDetector.name: YaraSignatureDetector,
    Ember2024Detector.name: Ember2024Detector,
    EmberMalwareDetector.name: EmberMalwareDetector,
    MalConvDetector.name: MalConvDetector,
    MalConvGCTDetector.name: MalConvGCTDetector,
}


class InspectionEngine:
    """Runs the layered inspection stage and produces a :class:`RiskReport`."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.block_threshold = float(cfg.inspection["block_threshold"])
        self.bands = int(cfg.integrity["risk_bands"])
        self.detectors: List[Detector] = []
        self._load_detectors()

    def _load_detectors(self) -> None:
        for name, dcfg in self.cfg.inspection["detectors"].items():
            if not dcfg.get("enabled", True):
                continue
            cls = REGISTRY.get(name)
            if cls is None:
                continue
            self.detectors.append(cls(dcfg.get("weight", 0.5), dcfg, self.cfg.root))

    def loaded_detectors(self) -> List[str]:
        return [f"{d.name}{'' if d.available else ' (UNAVAILABLE)'}"
                for d in self.detectors]

    def inspect(self, obj: TransferObject) -> RiskReport:
        results = [d.evaluate(obj) for d in self.detectors]
        votes = [(r.weight, r.score) for r in results if r.available]
        risk = noisy_or(votes)
        band, band_value = quantise(risk, self.bands)
        blocked = risk >= self.block_threshold
        return RiskReport(
            risk=risk, band=band, band_value=band_value,
            blocked=blocked, results=results,
        )
