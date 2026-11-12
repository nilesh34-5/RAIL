"""Risk aggregation (Eq. 1), quantisation (Eq. 5) and channel bound (Eq. 6)."""
import math

from railcds.risk import noisy_or
from railcds.quantize import quantise, channel_capacity_bound


def test_noisy_or_single_confident_detector_dominates():
    # five near-zero detectors + one confident one -> high risk (not the mean)
    votes = [(1.0, 0.02)] * 5 + [(1.0, 0.9)]
    r = noisy_or(votes)
    assert r > 0.9                      # ~0.91, not the average 0.16


def test_noisy_or_bounds_and_empty():
    assert noisy_or([]) == 0.0
    assert 0.0 <= noisy_or([(0.5, 0.5), (0.3, 0.8)]) <= 1.0
    # a fully-certain detector drives the score to 1
    assert noisy_or([(1.0, 1.0), (0.5, 0.1)]) == 1.0
    # weight 0 silences a detector
    assert noisy_or([(0.0, 1.0)]) == 0.0


def test_quantise_bands():
    B = 4
    assert quantise(0.0, B) == (0, 0.0)
    assert quantise(0.24, B)[0] == 0
    assert quantise(0.25, B)[0] == 1
    assert quantise(0.99, B)[0] == 3
    assert quantise(1.0, B) == (3, 0.75)     # top band index B-1
    # quantised value never exceeds the input
    for r in (0.1, 0.37, 0.62, 0.88):
        assert quantise(r, B)[1] <= r


def test_channel_bound():
    # 4 bands, 1 object/s -> 2 bit/s (paper's worked example)
    assert math.isclose(channel_capacity_bound(1.0, 4), 2.0)
