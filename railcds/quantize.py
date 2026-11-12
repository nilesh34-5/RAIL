"""Risk-band quantisation (Eq. 5) and the covert-channel bound (Eq. 6).

    r_tilde = floor(r * B) / B                (Eq. 5)
    C <= lambda * log2(B)                      (Eq. 6)

Quantising the continuous risk score to one of ``B`` bands is RAIL's defence
against the covert channel it would otherwise open: because chunk size and
anchoring cadence are visible from Network B, an attacker who can steer the
score could encode data in the resulting behaviour.  Collapsing the score to B
bands caps that channel at ``log2(B)`` bits per object.
"""
from __future__ import annotations

import math


def quantise(risk: float, bands: int) -> tuple[int, float]:
    """Return ``(band_index, band_value)`` for a continuous risk in [0,1].

    band_index is in ``[0, bands-1]``; band_value == band_index / bands is the
    r_tilde value fed to every downstream stage.
    """
    if bands < 1:
        raise ValueError("bands must be >= 1")
    r = min(max(risk, 0.0), 1.0)
    idx = int(math.floor(r * bands))
    if idx >= bands:        # r == 1.0 edge case -> top band
        idx = bands - 1
    return idx, idx / bands


def channel_capacity_bound(rate_lambda: float, bands: int) -> float:
    """Upper bound on covert-channel capacity in bits/second (Eq. 6)."""
    return rate_lambda * math.log2(bands)
