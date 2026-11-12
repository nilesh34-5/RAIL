"""EMBER2024 LightGBM malware detector (offline, pretrained, multi-format).

The recommended out-of-the-box supervised ML detector.  Uses the EMBER2024
benchmark model (Joyce et al.) via the ``thrember`` package: a pretrained
LightGBM classifier that returns a maliciousness probability from a 2568-feature
static analysis of the object.  The ``EMBER2024_all`` model is multi-format
(PE, ELF, PDF, APK, .NET, ...), so unlike the classic EMBER2018 model it can
score any transferred object, not only PE files.

Provision the model with::

    python scripts/download_models.py --ember2024

Availability requires: thrember, lightgbm, and the model file
(``models/ember2024/EMBER2024_all.model``).  If any is missing the detector is
skipped and the other layers carry the inspection.
"""
from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any, Dict, Tuple

from ..models import TransferObject
from .base import Detector


class Ember2024Detector(Detector):
    name = "ember2024_ml"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.model_path = cfg.get("model", "models/ember2024/EMBER2024_all.model")
        self._booster = None
        self._extractor = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        import lightgbm as lgb
        from thrember.features import PEFeatureExtractor

        path = Path(self.model_path)
        if not path.is_absolute():
            path = self.root / path
        if not path.exists():
            raise RuntimeError(f"EMBER2024 model not found at {path}")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._booster = lgb.Booster(model_file=str(path))
            self._extractor = PEFeatureExtractor()
        self._dim = self._booster.num_feature()

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        import numpy as np
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            feat = np.asarray(self._extractor.feature_vector(obj.data), dtype=np.float32)
            prob = float(self._booster.predict([feat])[0])
        prob = min(max(prob, 0.0), 1.0)
        return prob, f"EMBER2024 p(malicious)={prob:.3f}"
