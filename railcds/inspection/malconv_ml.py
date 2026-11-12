"""MalConv deep-learning detector (raw-byte CNN, PyTorch).

MalConv (Raff et al., 2018) classifies an object directly from its raw bytes -
an embedding over byte values followed by a gated strided convolution and a
global max-pool.  It performs no feature engineering at all, which makes it a
useful independent complement to the gradient-boosted EMBER models that score a
hand-designed 2568-dimension feature vector: the two families fail differently,
which is exactly what the Noisy-OR aggregation in Eq. (1) assumes.

Weights: the pretrained checkpoint distributed with ``secml_malware`` (PRALab,
University of Cagliari), provisioned by::

    python scripts/download_models.py --malconv

Availability requires torch plus the weights file; otherwise the detector marks
itself unavailable and the remaining layers carry the decision.
"""
from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any, Dict, Tuple

from ..models import TransferObject
from .base import Detector

MAX_LEN = 2 ** 20        # 1 MiB of bytes, MalConv's trained input length


class MalConvDetector(Detector):
    name = "malconv_ml"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.model_path = cfg.get("model", "models/malconv/pretrained_malconv.pth")
        self.max_len = int(cfg.get("max_bytes", MAX_LEN))
        self._model = None
        self._torch = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        import torch
        import numpy as np                       # noqa: F401 - used in score()
        from .malconv_net import MalConv, PADDING_VALUE  # noqa: F401

        if MalConv is None:
            raise RuntimeError("MalConv network unavailable (torch import failed)")
        path = Path(self.model_path)
        if not path.is_absolute():
            path = self.root / path
        if not path.exists():
            raise RuntimeError(f"MalConv weights not found at {path}")

        self._torch = torch
        model = MalConv()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            state = torch.load(str(path), map_location="cpu", weights_only=False)
        if isinstance(state, dict) and "model_state_dict" in state:
            state = state["model_state_dict"]
        model.load_state_dict(state, strict=True)
        model.eval()
        self._model = model

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        import numpy as np
        torch = self._torch
        from .malconv_net import PADDING_VALUE
        data = obj.data[:self.max_len]
        if not data:
            return 0.0, "empty object"
        # raw byte values (0-255), padded with 256 - the training convention
        arr = np.frombuffer(data, dtype=np.uint8).astype(np.int64)
        if arr.shape[0] < self.max_len:
            arr = np.pad(arr, (0, self.max_len - arr.shape[0]),
                         constant_values=PADDING_VALUE)
        x = torch.from_numpy(arr).unsqueeze(0)
        with torch.no_grad():
            prob = float(self._model(x).item())   # model already applies sigmoid
        prob = min(max(prob, 0.0), 1.0)
        return prob, f"MalConv p(malicious)={prob:.3f}"
