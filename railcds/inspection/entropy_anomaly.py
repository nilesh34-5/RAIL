"""Byte-distribution anomaly detector (offline, scikit-learn IsolationForest).

The model is trained once, offline, on a corpus of benign objects
(``scripts/train_anomaly.py``) and saved as a joblib file.  At runtime the
detector extracts the same 257-dimensional feature vector (256 normalised byte
frequencies + Shannon entropy) and maps the IsolationForest decision function to
a confidence in [0,1] - packed, encrypted or otherwise out-of-distribution
payloads score high.

If no trained model is present the detector degrades gracefully to a pure
Shannon-entropy heuristic so the pipeline still runs.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np

from ..models import TransferObject
from .base import Detector

FEATURE_DIM = 257  # 256 byte-frequency bins + entropy


def byte_features(data: bytes) -> np.ndarray:
    """257-dim feature: normalised byte histogram (256) + Shannon entropy (1)."""
    if not data:
        return np.zeros(FEATURE_DIM, dtype=np.float64)
    arr = np.frombuffer(data, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float64)
    total = hist.sum()
    freq = hist / total
    nz = freq[freq > 0]
    entropy = float(-(nz * np.log2(nz)).sum())        # 0..8 bits/byte
    feat = np.empty(FEATURE_DIM, dtype=np.float64)
    feat[:256] = freq
    feat[256] = entropy / 8.0                          # scale entropy to [0,1]
    return feat


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float64)
    freq = hist / hist.sum()
    nz = freq[freq > 0]
    return float(-(nz * np.log2(nz)).sum())


class EntropyAnomalyDetector(Detector):
    name = "entropy_anomaly"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.model_path = cfg.get("model", "models/anomaly_isoforest.joblib")
        self._clf = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        path = Path(self.model_path)
        if not path.is_absolute():
            path = self.root / path
        if path.exists():
            import joblib
            self._clf = joblib.load(path)
        # no model -> stay available but use the entropy heuristic

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        if self._clf is not None:
            feat = byte_features(obj.data).reshape(1, -1)
            df = float(self._clf.decision_function(feat)[0])
            # decision_function: >0 inlier, <0 outlier. Map to [0,1] smoothly.
            risk = 1.0 / (1.0 + math.exp(df * 8.0))
            return risk, f"isoforest df={df:+.3f}"
        # fallback heuristic: very high entropy suggests packed/encrypted payload
        ent = _shannon_entropy(obj.data)
        risk = max(0.0, (ent - 7.2) / 0.8)     # 7.2 bits -> 0, 8.0 bits -> 1
        return min(risk, 1.0), f"entropy={ent:.2f} bits/byte (heuristic)"
