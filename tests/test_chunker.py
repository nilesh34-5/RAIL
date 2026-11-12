"""Risk-adaptive chunking (Eq. 2)."""
from railcds.chunker import chunk_size_for_risk, chunk_object

C_MAX = 1_048_576
C_MIN = 16_384


def test_chunk_size_endpoints():
    assert chunk_size_for_risk(0.0, C_MAX, C_MIN) == C_MAX     # clean -> coarse
    assert chunk_size_for_risk(1.0, C_MAX, C_MIN) == C_MIN     # suspect -> fine


def test_chunk_size_monotone_decreasing():
    sizes = [chunk_size_for_risk(r / 10, C_MAX, C_MIN) for r in range(11)]
    assert all(sizes[i] >= sizes[i + 1] for i in range(len(sizes) - 1))


def test_geometric_midpoint():
    # r=0.5 -> geometric mean of the bounds
    mid = chunk_size_for_risk(0.5, C_MAX, C_MIN)
    assert abs(mid - int((C_MAX * C_MIN) ** 0.5)) <= 1


def test_chunk_object_lengths_and_count():
    data = b"A" * 1000
    chunks = chunk_object(data, 256)
    assert len(chunks) == 4                      # 256,256,256,232
    assert b"".join(c.data for c in chunks) == data
    assert [c.seq for c in chunks] == [0, 1, 2, 3]


def test_empty_object_single_chunk():
    chunks = chunk_object(b"", 256)
    assert len(chunks) == 1 and chunks[0].data == b""
