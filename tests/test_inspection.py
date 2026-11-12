"""Inspection engine sanity checks (uses whatever detectors are installed)."""
import os

import pytest

from railcds.config import load_config
from railcds.inspection.engine import InspectionEngine
from railcds.models import TransferObject


@pytest.fixture(scope="module")
def engine():
    return InspectionEngine(load_config())


def test_some_detector_available(engine):
    assert any(d.available for d in engine.detectors), \
        "no detectors available - run scripts/download_models.py"


def test_high_entropy_scores_above_benign_text(engine):
    benign = TransferObject(name="note.txt",
                            data=b"ordinary business text.\n" * 200)
    random_blob = TransferObject(name="blob.bin", data=os.urandom(64 * 1024))
    r_benign = engine.inspect(benign)
    r_random = engine.inspect(random_blob)
    assert r_random.risk >= r_benign.risk
    assert 0.0 <= r_benign.risk <= 1.0 and 0.0 <= r_random.risk <= 1.0


def test_polyglot_flagged(engine):
    poly = TransferObject(
        name="doc.pdf",
        data=b"%PDF-1.4\n...body...\nPK\x03\x04zip\nMZ program\n%%EOF",
    )
    report = engine.inspect(poly)
    ft = next((d for d in report.results if d.name == "file_type"), None)
    if ft and ft.available:
        assert ft.score >= 0.5      # polyglot detector should fire
