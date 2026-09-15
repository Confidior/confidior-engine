from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.export.measurement import (
    MeasurementResult,
    evidence_class_for_workload,
    extract_measurement,
    load_registry,
    verify_measurement,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REGISTRY_PATH = FIXTURES / "registry" / "sample_registry.yaml"
SEVSNP_FIXTURE = FIXTURES / "sevsnp" / "sample_report.hex"
TDX_FIXTURE = FIXTURES / "tdx" / "sample_quote.hex"
NITRO_FIXTURE = FIXTURES / "nitro" / "sample_attestation.hex"
REAL_SEVSNP_FIXTURE = FIXTURES / "sevsnp" / "real_sev_snp.hex"
REAL_NITRO_FIXTURE = FIXTURES / "nitro" / "aws-c6g-nitro-attestation.hex"
REDPILL_TDX_FIXTURE = FIXTURES / "tdx" / "redpill-gateway-quote.hex"
PROD_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "data" / "registry.yaml"


def test_load_registry():
    workloads = load_registry(str(REGISTRY_PATH))
    assert "sevsnp-demo-vm" in workloads
    assert workloads["sevsnp-demo-vm"]["platform"] == "AMD-SEV-SNP"


def test_load_registry_invalid_path():
    with pytest.raises(FileNotFoundError):
        load_registry("/nonexistent/registry.yaml")


def test_verify_sevsnp_match():
    hex_data = SEVSNP_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="sevsnp",
        workload="sevsnp-demo-vm",
        registry_path=str(REGISTRY_PATH),
    )
    assert isinstance(result, MeasurementResult)
    assert result.workload == "sevsnp-demo-vm"
    assert result.platform == "sevsnp"
    assert result.match is True
    assert result.error is None


def test_verify_sevsnp_mismatch():
    hex_data = SEVSNP_FIXTURE.read_text()
    # Modify the expected measurement to be different
    workloads = yaml.safe_load(REGISTRY_PATH.read_text())
    workloads["workloads"]["sevsnp-demo-vm"]["measurement"] = "bb" * 48
    REGISTRY_PATH.write_text(yaml.dump(workloads))
    try:
        result = verify_measurement(
            hex_data=hex_data,
            platform="sevsnp",
            workload="sevsnp-demo-vm",
            registry_path=str(REGISTRY_PATH),
        )
        assert result.match is False
    finally:
        # Restore
        workloads["workloads"]["sevsnp-demo-vm"]["measurement"] = "aa" * 48
        REGISTRY_PATH.write_text(yaml.dump(workloads))


def test_verify_workload_not_found():
    hex_data = SEVSNP_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="sevsnp",
        workload="nonexistent-workload",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is False
    assert result.error is not None
    assert "not found" in result.error


def test_extract_measurement_sevsnp():
    hex_data = SEVSNP_FIXTURE.read_text()
    measurement = extract_measurement(hex_data, "sevsnp")
    assert len(measurement) == 96  # 48 bytes = 96 hex chars
    assert measurement == "aa" * 48


def test_extract_measurement_tdx():
    hex_data = TDX_FIXTURE.read_text()
    measurement = extract_measurement(hex_data, "tdx")
    assert len(measurement) == 96
    assert measurement == "aa" * 48


def test_extract_measurement_nitro():
    hex_data = NITRO_FIXTURE.read_text()
    measurement = extract_measurement(hex_data, "nitro")
    assert isinstance(measurement, str)
    assert len(measurement) > 0


def test_extract_measurement_unknown_platform():
    with pytest.raises(ValueError, match="Unknown platform"):
        extract_measurement("aa", "unknown")


def test_verify_tdx_match():
    hex_data = TDX_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="tdx",
        workload="tdx-demo-vm",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is True


def test_verify_nitro_match():
    hex_data = NITRO_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="nitro",
        workload="nitro-demo-vm",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is True


def test_verify_real_sevsnp_match():
    """Real AWS c6a SEV-SNP quote verifies against its captured measurement."""
    hex_data = REAL_SEVSNP_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="sevsnp",
        workload="aws-c6a-sev-snp",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is True
    assert result.error is None
    assert result.source == "first-capture"


def test_verify_real_nitro_match():
    """Real AWS c6g Nitro quote verifies against its captured measurement."""
    hex_data = REAL_NITRO_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="nitro",
        workload="aws-c6g-nitro",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is True
    assert result.error is None
    assert result.source == "first-capture"


def test_verify_real_sevsnp_wrong_workload():
    """Real SEV-SNP quote against the Nitro workload must mismatch (platform guard)."""
    hex_data = REAL_SEVSNP_FIXTURE.read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="sevsnp",
        workload="aws-c6g-nitro",
        registry_path=str(REGISTRY_PATH),
    )
    assert result.match is False
    assert result.error is not None
    assert "Platform mismatch" in result.error


def test_prod_registry_has_real_aws_entries():
    """Production registry must carry the real AWS entries, not synthetic-only."""
    workloads = load_registry(str(PROD_REGISTRY_PATH))
    assert "aws-c6a-sev-snp" in workloads
    assert "aws-c6g-nitro" in workloads
    assert workloads["aws-c6a-sev-snp"]["source"] == "first-capture"
    assert workloads["aws-c6g-nitro"]["source"] == "first-capture"


def test_prod_registry_real_entries_verify_against_real_quotes():
    """Production registry entries must match the real captured quotes."""
    sevsnp = verify_measurement(
        hex_data=REAL_SEVSNP_FIXTURE.read_text(),
        platform="sevsnp",
        workload="aws-c6a-sev-snp",
        registry_path=str(PROD_REGISTRY_PATH),
    )
    assert sevsnp.match is True
    nitro = verify_measurement(
        hex_data=REAL_NITRO_FIXTURE.read_text(),
        platform="nitro",
        workload="aws-c6g-nitro",
        registry_path=str(PROD_REGISTRY_PATH),
    )
    assert nitro.match is True


def test_compute_tdx_blocked_honest_finding():
    """TDX compute path reports the honest finding, not a fabricated value."""
    from src.export.measurement import compute_tdx

    result = compute_tdx()
    assert result.status == "blocked"
    assert result.blocker_kind == "missing-artifacts"
    assert result.measurement == ""


def test_compute_nitro_blocked_without_eif():
    """Nitro compute path blocks without a preserved EIF."""
    from src.export.measurement import compute_nitro

    result = compute_nitro()
    assert result.status == "blocked"
    assert result.blocker_kind == "missing-artifacts"


def test_prod_registry_has_vendor_entries():
    """Production registry carries vendor-published + vendor-captured entries."""
    workloads = load_registry(str(PROD_REGISTRY_PATH))
    assert "tinfoil-tdx-medium-1d" in workloads
    assert workloads["tinfoil-tdx-medium-1d"]["source"] == "vendor-published"
    assert "redpill-gateway-tdx" in workloads
    assert workloads["redpill-gateway-tdx"]["source"] == "vendor-captured"


def test_redpill_quote_extracts_and_matches():
    """Real RedPill TDX quote fixture extracts to the registry MRTD and matches."""
    hex_data = REDPILL_TDX_FIXTURE.read_text()
    measurement = extract_measurement(hex_data, "tdx")
    assert len(measurement) == 96
    result = verify_measurement(
        hex_data=hex_data,
        platform="tdx",
        workload="redpill-gateway-tdx",
        registry_path=str(PROD_REGISTRY_PATH),
    )
    assert result.match is True
    assert result.source == "vendor-captured"


def test_check_tcb_lag_reports_behind(tmp_path):
    """A quote TCB below a CVE's fix threshold reports the lag."""
    from src.core.attacks import TEE_ATTACKS
    from src.core.taxonomy import Platform
    from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list
    from src.tools.cve_tcb_mapper import check_tcb_lag

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP", version="0.0.1.20", release_date="2024-12-11",
            status="current", cve_id="CVE-2024-21944",
            advisory_url="https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6010.html",
        )
    )
    try:
        lag = check_tcb_lag(db, Platform.AMDSEVSNP, "0.0.1.10")
        assert len(lag) == 1
        assert lag[0].cve_id == "CVE-2024-21944"
        assert lag[0].months_behind is not None and lag[0].months_behind > 0
    finally:
        db.close()


def test_check_tcb_lag_up_to_date(tmp_path):
    """A quote TCB at/above the fix threshold reports no lag."""
    from src.core.attacks import TEE_ATTACKS
    from src.core.taxonomy import Platform
    from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list
    from src.tools.cve_tcb_mapper import check_tcb_lag

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP", version="0.0.1.20", release_date="2024-12-11",
            status="current", cve_id="CVE-2024-21944",
        )
    )
    try:
        lag = check_tcb_lag(db, Platform.AMDSEVSNP, "0.0.1.20")
        assert lag == []
    finally:
        db.close()


def test_check_tcb_lag_empty_db(tmp_path):
    """No TCB records -> no lag reported."""
    from src.core.taxonomy import Platform
    from src.tools.archaeology import ArchaeologyDB
    from src.tools.cve_tcb_mapper import check_tcb_lag

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    try:
        lag = check_tcb_lag(db, Platform.AMDSEVSNP, "0.0.1.10")
        assert lag == []
    finally:
        db.close()


def test_extract_fix_version_from_description():
    """CVE descriptions carrying 'before version X' yield the fix version."""
    from src.tools.cve_tcb_mapper import extract_fix_version

    assert extract_fix_version("Improper input validation before version 1.5.05.46.698 may allow") == "1.5.05.46.698"  # noqa: E501
    assert extract_fix_version("Use after free in versions before 3.1.80 and 4.0.30") == "3.1.80"  # noqa: E501
    assert extract_fix_version("Prior to version 0.0.1.20, an attacker could") == "0.0.1.20"  # noqa: E501
    assert extract_fix_version("Fixed in version 2.1.0") == "2.1.0"
    assert extract_fix_version("No fix version mentioned in this prose") is None


def test_measure_cli_reports_tcb_lag(tmp_path, capsys):
    """confidior measure --tcb reports the lag end-to-end via the CLI."""
    import sys

    from src.core.attacks import TEE_ATTACKS
    from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list
    from src.tools.cve_tcb_mapper import (
        extract_fix_version,  # noqa: F401 (module import path check)
    )

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP", version="0.0.1.20", release_date="2024-12-11",
            status="current", cve_id="CVE-2024-21944",
        )
    )
    db.close()

    from src.cli.main import main
    sys.argv = [
        "confidior", "measure",
        "--input", "tests/fixtures/sevsnp/real_sev_snp.hex",
        "--platform", "sevsnp",
        "--workload", "aws-c6a-sev-snp",
        "--registry", "data/registry.yaml",
        "--tcb", "0.0.1.10",
        "--db-path", str(tmp_path / "arch.db"),
    ]
    rc = main()
    out = capsys.readouterr().out
    assert rc == 1  # lag => nonzero exit
    assert "TCB: N months behind" in out
    assert "CVE-2024-21944" in out

def test_extract_tcb_version_sevsnp():
    """The TCB version is extracted from a real SEV-SNP quote."""
    from src.export.measurement import extract_tcb_version

    hex_data = Path("tests/fixtures/sevsnp/real_sev_snp.hex").read_text()
    tcb = extract_tcb_version(hex_data, "sevsnp")
    assert tcb is not None
    assert len(tcb) > 0


def test_extract_tcb_version_tdx():
    """The TCB version is extracted from a real TDX quote."""
    from src.export.measurement import extract_tcb_version

    hex_data = Path("tests/fixtures/tdx/redpill-gateway-quote.hex").read_text()
    tcb = extract_tcb_version(hex_data, "tdx")
    assert tcb is not None
    assert len(tcb) > 0


def test_extract_tcb_version_nitro_none():
    """Nitro has no SVN concept; the temporal signal is the measurement match."""
    from src.export.measurement import extract_tcb_version

    hex_data = Path("tests/fixtures/nitro/aws-c6g-nitro-attestation.hex").read_text()
    assert extract_tcb_version(hex_data, "nitro") is None


def test_verify_measurement_populates_tcb(tmp_path):
    """verify_measurement returns the quote's TCB version alongside the match."""
    from src.export.measurement import verify_measurement

    hex_data = Path("tests/fixtures/sevsnp/real_sev_snp.hex").read_text()
    result = verify_measurement(
        hex_data=hex_data,
        platform="sevsnp",
        workload="aws-c6a-sev-snp",
        registry_path="data/registry.yaml",
    )
    assert result.match is True
    assert result.tcb_version is not None


def test_measure_cli_autodetects_tcb(tmp_path):
    """The measure CLI reports the temporal lag without --tcb, auto-detecting
    the TCB version from the quote (regression: the flag used to be required)."""
    import subprocess
    import sys

    from src.core.attacks import TEE_ATTACKS
    from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP", version="0.0.1.20", release_date="2024-12-11",
            status="current", cve_id="CVE-2024-21944",
        )
    )
    db.close()

    proc = subprocess.run(
        [
            sys.executable, "-m", "src.cli.main", "measure",
            "--input", "tests/fixtures/sevsnp/real_sev_snp.hex",
            "--platform", "sevsnp",
            "--workload", "aws-c6a-sev-snp",
            "--registry", "data/registry.yaml",
            "--db-path", str(tmp_path / "arch.db"),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert "TCB:" in proc.stdout, f"lag check did not run: {proc.stdout} {proc.stderr}"


class TestRegistryEvidenceClass:
    """Registry provenance becomes the evidence class the grade reports."""

    def test_source_values_map_onto_the_ladder(self):
        from src.core.taxonomy import EvidenceClass

        assert (
            EvidenceClass.from_registry_source("first-capture") == EvidenceClass.CAPTURED
        )
        assert (
            EvidenceClass.from_registry_source("vendor-captured")
            == EvidenceClass.VENDOR_CAPTURED
        )
        assert (
            EvidenceClass.from_registry_source("vendor-published")
            == EvidenceClass.VENDOR_PUBLISHED
        )
        # A fixture is not evidence about anyone's provenance.
        assert EvidenceClass.from_registry_source("Synthetic fixture") == EvidenceClass.UNKNOWN
        assert EvidenceClass.from_registry_source(None) == EvidenceClass.UNKNOWN

    def test_computed_match_outranks_where_the_value_came_from(self):
        from src.core.taxonomy import EvidenceClass

        entry = {
            "source": "vendor-published",
            "verification": "computed-vs-published MATCH (4/4 platforms)",
        }
        assert EvidenceClass.from_registry_entry(entry) == EvidenceClass.COMPUTED_GOLDEN

        partial = {
            "source": "vendor-published",
            "verification": "computed-vs-published MISMATCH on RTMR1",
        }
        assert EvidenceClass.from_registry_entry(partial) == EvidenceClass.VENDOR_PUBLISHED

    def test_workload_lookup_reads_the_shipped_registry(self):
        from src.core.taxonomy import EvidenceClass

        registry = Path(__file__).parent.parent / "data" / "registry.yaml"
        assert (
            evidence_class_for_workload(registry, "tinfoil-tdx-medium-1d")
            == EvidenceClass.COMPUTED_GOLDEN
        )
        assert (
            evidence_class_for_workload(registry, "redpill-gateway-tdx")
            == EvidenceClass.VENDOR_CAPTURED
        )
        assert (
            evidence_class_for_workload(registry, "aws-c6g-nitro") == EvidenceClass.CAPTURED
        )

    def test_unknown_cases_stay_unknown(self):
        from src.core.taxonomy import EvidenceClass

        registry = Path(__file__).parent.parent / "data" / "registry.yaml"
        # A named workload the registry does not hold, no name at all, and a
        # missing registry file all mean the same thing: nothing was stated.
        assert evidence_class_for_workload(registry, "not-a-workload") == EvidenceClass.UNKNOWN
        assert evidence_class_for_workload(registry, None) == EvidenceClass.UNKNOWN
        assert evidence_class_for_workload("/nonexistent.yaml", "x") == EvidenceClass.UNKNOWN
