"""MalConv network definition (Raff et al., 2018).

Layer names and the forward pass mirror the reference
implementation shipped with ``secml_malware`` (PRALab), so its published
``pretrained_malconv.pth`` checkpoint loads with ``strict=True`` and reproduces
upstream scores exactly.

Topology: byte embedding -> two parallel strided 1-D convolutions forming a
gated unit (ReLU on the value branch, sigmoid on the gate) -> global max-pool
over the sequence -> fully connected head -> sigmoid.  No feature engineering:
the model reads raw bytes.

Byte convention (must match training): bytes are used **unshifted** (0-255) and
the sequence is padded with the value **256**; the embedding therefore has 257
rows.  Shifting the bytes instead - a convention some MalConv ports use - makes
the pretrained weights produce meaningless scores.

Kept in its own module so it is imported only when PyTorch is available.
"""
from __future__ import annotations

#: value used to pad a byte sequence up to the model's fixed input length
PADDING_VALUE = 256

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    class MalConv(nn.Module):
        """MalConv with secml-compatible parameter names; outputs a probability."""

        def __init__(self, input_length: int = 2 ** 20, window_size: int = 500,
                     channels: int = 128, embd_size: int = 8) -> None:
            super().__init__()
            # 257 rows: 0-255 for byte values, 256 for padding
            self.embedding_1 = nn.Embedding(num_embeddings=257,
                                            embedding_dim=embd_size)
            self.conv1d_1 = nn.Conv1d(embd_size, channels, window_size,
                                      stride=window_size, bias=True)
            self.conv1d_2 = nn.Conv1d(embd_size, channels, window_size,
                                      stride=window_size, bias=True)
            self.dense_1 = nn.Linear(channels, channels)
            self.dense_2 = nn.Linear(channels, 1)
            self.input_length = input_length

        def forward(self, x):
            # x: (B, L) int64 raw byte values, padded with PADDING_VALUE
            x = self.embedding_1(x.long())               # (B, L, E)
            x = torch.transpose(x, 1, 2)                  # (B, E, L)
            value = torch.relu(self.conv1d_1(x))          # value branch
            gate = torch.sigmoid(self.conv1d_2(x))        # gate branch
            x = value * gate
            x = F.max_pool1d(x, kernel_size=x.size()[2:])  # global max-pool
            x = x.view(x.size(0), -1)
            x = torch.relu(self.dense_1(x))
            return torch.sigmoid(self.dense_2(x)).squeeze(-1)   # (B,) probability

except Exception:      # noqa: BLE001 - torch absent; detector stays unavailable
    MalConv = None      # type: ignore
