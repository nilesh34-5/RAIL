"""MalConvGCT deep-learning detector (global-channel-gating byte CNN).

MalConvGCT (Raff et al., 2021, "Classifying Sequences of Extreme Length with
Constant Memory Applied to Malware Detection") extends MalConv with a global
channel gating mechanism and a low-memory convolution scheme, letting it attend
across sequences far longer than the original 1 MiB window while keeping memory
constant.  It is the stronger of the two byte-level models.

The network definition is vendored (Apache-2.0 licence; only the imports were
made package-relative) from the authors' repository under
``railcds/inspection/vendor/malconv2``; only the pretrained checkpoint is
downloaded.  Provision with::

    python scripts/download_models.py --malconvgct
"""
from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any, Dict, Tuple

from ..models import TransferObject
from .base import Detector

MAX_LEN = 16_000_000     # cap the byte sequence so one object cannot stall S2


class MalConvGCTDetector(Detector):
    name = "malconvgct_ml"

    def __init__(self, weight: float, cfg: Dict[str, Any], root) -> None:
        self.model_path = cfg.get("model", "models/malconv/malconvGCT_nocat.checkpoint")
        self.max_len = int(cfg.get("max_bytes", MAX_LEN))
        self._model = None
        self._torch = None
        super().__init__(weight, cfg, root)

    def setup(self) -> None:
        import torch
        from .vendor.malconv2.MalConvGCT_nocat import MalConvGCT

        path = Path(self.model_path)
        if not path.is_absolute():
            path = self.root / path
        if not path.exists():
            raise RuntimeError(f"MalConvGCT checkpoint not found at {path}")

        self._torch = torch
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ck = torch.load(str(path), map_location="cpu", weights_only=False)
        # rebuild with the hyperparameters the checkpoint was trained under
        model = MalConvGCT(
            channels=ck.get("channels", 256),
            window_size=ck.get("filter_size", 256),
            stride=ck.get("stride", 64),
            embd_size=ck.get("embd_dim", 8),
        )
        result = model.load_state_dict(ck["model_state_dict"], strict=False)
        if result.missing_keys:
            raise RuntimeError(f"checkpoint missing {len(result.missing_keys)} keys")
        model.eval()
        self._model = model

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        import numpy as np
        torch = self._torch
        data = obj.data[:self.max_len]
        if not data:
            return 0.0, "empty object"
        # byte values shifted by +1; index 0 is the padding symbol
        arr = np.frombuffer(data, dtype=np.uint8).astype(np.int64) + 1
        x = torch.from_numpy(arr).unsqueeze(0)
        with torch.no_grad():
            out = self._model(x)
            logits = out[0] if isinstance(out, tuple) else out
            prob = float(torch.softmax(logits, dim=-1)[0, 1].item())
        prob = min(max(prob, 0.0), 1.0)
        return prob, f"MalConvGCT p(malicious)={prob:.3f}"
