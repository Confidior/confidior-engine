import json
import tempfile
from pathlib import Path

from src.cli.main import main


def test_end_to_end_tdx_verify():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        exit_code = main([
            "verify",
            "--input", "tests/fixtures/tdx/sample_quote.hex",
            "--platform", "tdx",
            "--policy", "tests/fixtures/policy/default.yaml",
            "--output-dir", str(tmpdir),
            "--workload", "test-e2e",
        ])

        assert exit_code == 0

        bundle_path = tmpdir / "evidence_bundle.json"
        assert bundle_path.exists()

        with open(bundle_path) as f:
            bundle_data = json.load(f)

        assert bundle_data["workload"] == "test-e2e"
        assert bundle_data["policy_evaluation"]["decision"] == "ALLOW"
        assert bundle_data["assurance"]["level"] == 2
        assert bundle_data["assurance"]["residual_risk"] == "CRITICAL"
        assert "TEE.fail" in bundle_data["assurance"]["boundary_statement"]
        assert len(bundle_data["signatures"]) == 1
        assert bundle_data["signatures"][0]["algorithm"] == "Ed25519"

        report_path = tmpdir / "report.md"
        assert report_path.exists()
        report_text = report_path.read_text()
        assert "Intel-TDX" in report_text
        assert "Level 2" in report_text

        badge_path = tmpdir / "badge.svg"
        assert badge_path.exists()
        badge_text = badge_path.read_text()
        assert "<svg" in badge_text
        assert "Level 2" in badge_text
