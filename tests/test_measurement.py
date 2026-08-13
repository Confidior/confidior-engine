from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.export.measurement import (
    MeasurementResult,
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
