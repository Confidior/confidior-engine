"""One clock, one format: the tests that keep timestamps reproducible."""

from __future__ import annotations

import ast
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from src.core.clock import utc_now, utc_now_iso
from src.tools.archaeology import ArchaeologyDB, TCBRecord

SRC = Path(__file__).resolve().parent.parent / "src"

#: The one module allowed to read the wall clock.
CLOCK_MODULE = SRC / "core" / "clock.py"


def test_utc_now_is_timezone_aware_and_utc():
    now = utc_now()

    assert now.tzinfo is not None
    assert now.utcoffset() == timezone.utc.utcoffset(None)


def test_utc_now_iso_round_trips_as_a_utc_instant():
    parsed = datetime.fromisoformat(utc_now_iso())

    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_archaeology_stamps_a_utc_instant_when_parsed_at_is_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = ArchaeologyDB(Path(tmpdir) / "tcb.db")
        db.insert(TCBRecord(platform="Intel-TDX", version="1.5.0", status="current"))

        stamped = db.query()[0].parsed_at
        db.close()

    assert stamped is not None
    parsed = datetime.fromisoformat(stamped)
    assert parsed.tzinfo is not None, f"parsed_at is naive: {stamped!r}"
    assert parsed.utcoffset().total_seconds() == 0


def _direct_clock_reads(path: Path) -> list[str]:
    """Every `datetime.now()` / `utcnow()` call in *path*, as source lines."""
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        if func.attr not in ("now", "utcnow"):
            continue
        # Only the stdlib clock matters: `datetime.now()`, `X.datetime.now()`.
        base = func.value
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if name == "datetime":
            found.append(f"{path}:{node.lineno}: {func.attr}()")
    return found


def test_only_the_clock_module_reads_the_wall_clock():
    """A second clock read is a second format, eventually.

    The engine's timestamps are reproducible only if they come from one place.
    This fails the moment a new `datetime.now()` is added outside `clock.py`,
    which is the point: the defect is silent otherwise.
    """
    offenders: list[str] = []
    for module in sorted(SRC.rglob("*.py")):
        if module == CLOCK_MODULE or "__pycache__" in module.parts:
            continue
        offenders.extend(_direct_clock_reads(module))

    assert offenders == [], "read the wall clock through src.core.clock:\n" + "\n".join(offenders)
