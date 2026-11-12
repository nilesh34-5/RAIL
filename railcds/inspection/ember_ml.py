"""EMBER LightGBM malware detector (offline, static PE analysis).

Loads the pretrained EMBER 2018 LightGBM booster and scores the 2381-dim
feature vector from :mod:`ember_features`.  EMBER is a *PE* model, so this
detector only scores objects that begin with the ``MZ`` DOS header; anything
else is reported with score 0 and detail "not a PE" (the layered pipeline has
other detectors for non-PE content).

Availability requires: lightgbm, lief, and the model file
(``models/ember/ember_model_2018.txt``, fetched by scripts/download_models.py).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

from ..models import TransferObject
from .base import Detector


class EmberMalwareDetector(Detector):
    name = "ember_ml"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.model_path = cfg.get("model", "models/ember/ember_model_2018.txt")
        self._booster = None
        self._extract = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        import lightgbm as lgb          # raises if not installed
        from . import ember_features    # raises if lief/sklearn missing

        path = Path(self.model_path)
        if not path.is_absolute():
            path = self.root / path
        if not path.exists():
            raise RuntimeError(f"EMBER model not found at {path}")
        self._booster = lgb.Booster(model_file=str(path))
        if self._booster.num_feature() != ember_features.FEATURE_DIM:
            raise RuntimeError(
                f"model expects {self._booster.num_feature()} features, "
                f"extractor produces {ember_features.FEATURE_DIM}"
            )
        self._extract = ember_features.extract_features

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        data = obj.data
        if len(data) < 2 or data[:2] != b"MZ":
            return 0.0, "not a PE (skipped)"
        feat = self._extract(data).reshape(1, -1)
        prob = float(self._booster.predict(feat)[0])
        prob = min(max(prob, 0.0), 1.0)
        return prob, f"EMBER p(malware)={prob:.3f}"
