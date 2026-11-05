"""Shared test configuration.

The BSI C5 catalogue lives under ``data/c5/`` and is not redistributed with the
engine: it is CC BY-ND non-commercial, the engine is Apache 2.0. Tests that read
it are skipped when it is absent, which is the state of a fresh clone. Tests
that assert behaviour *for* missing data do not carry the marker, because they
must run either way.
"""

from pathlib import Path

import pytest

C5_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "c5" / "v2026-04-bsi"

requires_c5_data = pytest.mark.skipif(
    not C5_DATA_DIR.is_dir(),
    reason="BSI C5 catalogue not present; it is not redistributed with the engine",
)
