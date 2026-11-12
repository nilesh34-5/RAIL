"""Noisy-OR risk aggregation (Eq. 1).

    r(O) = 1 - prod_i ( 1 - w_i * s_i(O) )

Averaging detector scores lets a crowd of confident-clean detectors bury one
confident-malicious detector.  Noisy-OR instead asks the probability that *none*
of the detectors is right, so a single confident detection alone drives the
score toward 1 ("OR").  The result is always in [0,1] because every factor is.
"""
from __future__ import annotations

from typing import Iterable, Tuple


def noisy_or(votes: Iterable[Tuple[float, float]]) -> float:
    """Combine ``(weight, score)`` pairs via Noisy-OR.

    Each ``weight`` and ``score`` is clamped to [0,1] defensively.
    An empty set of votes yields 0.0 (no evidence -> not risky).
    """
    product = 1.0
    any_vote = False
    for weight, score in votes:
        any_vote = True
        w = min(max(weight, 0.0), 1.0)
        s = min(max(score, 0.0), 1.0)
        product *= (1.0 - w * s)
    if not any_vote:
        return 0.0
    return 1.0 - product
