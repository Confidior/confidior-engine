"""CLI command tests: the __main__ entry, freshness, attacks sync/map, error paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cli.main import main

TDX_FIXTURE = Path(__file__).parent / "fixtures" / "tdx" / "sample_quote.hex"
POLICY = Path(__file__).parent / "fixtures" / "policy" / "default.yaml"


def _run(argv: list[str]) -> int:
    return main(argv)


def test_main_has_entry_guard():
    """python -m src.cli.main must call main() — the module needs the __main__ guard."""
    import runpy
    import sys

    sys.argv = ["src.cli.main", "--help"]
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("src.cli.main", run_name="__main__")
    # argparse --help exits 0
    assert exc.value.code == 0


def test_verify_invalid_input_returns_1(capsys):
    code = _run(
        [
            "verify",
            "--input",
            "/tmp/definitely-missing.hex",
            "--platform",
            "tdx",
            "--policy",
            str(POLICY),
        ]
    )
    assert code == 1
    assert "input file not found" in capsys.readouterr().err


def test_verify_missing_policy_errors():
    with pytest.raises(SystemExit):
        _run(["verify", "--input", str(TDX_FIXTURE), "--platform", "tdx"])


def test_measure_unknown_workload_returns_1(capsys):
    code = _run(
        [
            "measure",
            "--input",
            str(TDX_FIXTURE),
            "--platform",
            "tdx",
            "--workload",
            "nope",
            "--registry",
            "data/registry.yaml",
        ]
    )
    assert code == 1
    assert "not found in registry" in capsys.readouterr().out


def test_freshness_missing_bundle_returns_1(capsys):
    code = _run(["freshness", "--input", "/tmp/definitely-missing-bundle.json"])
    assert code == 1
    assert "bundle file not found" in capsys.readouterr().err


def test_freshness_reports_fresh(tmp_path):
    """A bundle whose attack DB snapshot matches the current DB reports FRESH."""
    from datetime import datetime, timedelta

    from src.core.attacks import compute_attack_db_snapshot
    from src.core.taxonomy import EvidenceBundle

    bundle = EvidenceBundle(
        bundle_id="fresh-test",
        timestamp=datetime.now(),
        expires_at=datetime.now() + timedelta(days=30),
        workload="test",
        attack_db_snapshot=compute_attack_db_snapshot(),
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle.to_dict()))

    code = _run(["freshness", "--input", str(path)])
    assert code == 0


def test_freshness_unknown_snapshot_returns_1(tmp_path, capsys):
    """A bundle with no attack DB snapshot reports UNKNOWN and returns 1."""
    from datetime import datetime, timedelta

    from src.core.taxonomy import EvidenceBundle

    bundle = EvidenceBundle(
        bundle_id="nosnap-test",
        timestamp=datetime.now(),
        expires_at=datetime.now() + timedelta(days=30),
        workload="test",
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle.to_dict()))

    code = _run(["freshness", "--input", str(path)])
    assert code == 1
    assert "no attack DB snapshot" in capsys.readouterr().out


def test_attacks_map_cve_tcb_missing_db_returns_1(capsys):
    code = _run(["attacks", "map-cve-tcb", "--db-path", "/tmp/definitely-missing.db"])
    assert code == 1
    assert "archaeology DB not found" in capsys.readouterr().err


def test_attacks_sync_nvd_dry_run(monkeypatch, capsys):
    """attacks sync --source nvd --dry-run fetches + lists without inserting."""

    class FakeCVE:
        cve_id = "CVE-2024-0001"
        year = 2024
        impact = "test impact"

    def fake_fetch():
        return [{"cve_id": "CVE-2024-0001", "year": 2024, "impact": "test impact"}]

    def fake_record(c):
        return FakeCVE()

    monkeypatch.setattr("scripts.fetch_tee_cves.fetch_cves_nvd", fake_fetch)
    monkeypatch.setattr("scripts.fetch_tee_cves.nvd_to_attack_record", fake_record)

    code = _run(["attacks", "sync", "--source", "nvd", "--dry-run"])
    assert code == 0
    assert "CVE-2024-0001" in capsys.readouterr().out
