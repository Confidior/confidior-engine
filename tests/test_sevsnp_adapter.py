import os
import tempfile
from pathlib import Path

import pytest

from src.core.taxonomy import NodeType, Platform, TCBStatus
from src.ingest.adapters.sevsnp import (
    parse_sevsnp_report,
    verify_sevsnp_report,
    _prepare_vlek_certs,
    _verify_report_vlek,
)

_FIXTURE_DIR = Path("tests/fixtures/sevsnp")
_VLEK_CERT_ENV = os.environ.get("CONFIDIOR_TEST_VLEK_CERT")
_VLEK_CERT = (
    Path(_VLEK_CERT_ENV) if _VLEK_CERT_ENV
    else _FIXTURE_DIR / "vlek" / "vlek.pem"
)
_VLEK_CHAIN = _VLEK_CERT.parent / "vlek_chain.pem"
_VLEK_CHAIN = _VLEK_CHAIN if _VLEK_CHAIN.exists() else None
_REAL_SEV_SNP = _FIXTURE_DIR / "real_sev_snp.hex"


def test_verify_sevsnp_rejects_synthetic_with_vlek():
    if not _VLEK_CERT.exists():
        pytest.skip("VLEK fixture not found")
    with open("tests/fixtures/sevsnp/sample_report.hex") as f:
        hex_data = f.read()

    result = verify_sevsnp_report(
        hex_data, product="milan", vlek_cert=_VLEK_CERT or None,
    )

    assert result["valid"] is False
    assert "error" in result


def test_prepare_vlek_certs_downloads_and_splits_chain():
    if not _VLEK_CERT.exists():
        pytest.skip("VLEK fixture not found: set CONFIDIOR_TEST_VLEK_CERT")

    tmpdir = Path(tempfile.mkdtemp())
    err = _prepare_vlek_certs(tmpdir, "milan", _VLEK_CERT, chain_path=_VLEK_CHAIN)

    assert err is None, f"_prepare_vlek_certs failed: {err}"
    assert (tmpdir / "vcek.pem").exists()
    assert (tmpdir / "ark.pem").exists()
    assert (tmpdir / "ask.pem").exists()

    # Verify each PEM loads as a valid X.509 certificate
    from cryptography import x509
    import warnings
    for name in ("vcek.pem", "ark.pem", "ask.pem"):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=".*serial number.*")
            cert = x509.load_pem_x509_certificate((tmpdir / name).read_bytes())
        assert cert.subject is not None


def test_verify_report_vlek_validates_real_attestation():
    if not _VLEK_CERT.exists() or not _REAL_SEV_SNP.exists():
        pytest.skip("VLEK or SEV-SNP fixture not found")

    tmpdir = Path(tempfile.mkdtemp())
    _prepare_vlek_certs(tmpdir, "milan", _VLEK_CERT, chain_path=_VLEK_CHAIN)

    from sev_pytools.certs import load_certificates
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*serial number.*")
        certs = load_certificates(tmpdir)

    hex_data = _REAL_SEV_SNP.read_text()
    raw_bytes = bytes.fromhex(hex_data.strip())

    err = _verify_report_vlek(raw_bytes, certs)
    assert err is None, f"_verify_report_vlek failed: {err}"


def test_verify_sevsnp_with_vlek_passes_on_real_attestation():
    if not _VLEK_CERT.exists() or not _REAL_SEV_SNP.exists():
        pytest.skip("VLEK or SEV-SNP fixture not found")

    hex_data = _REAL_SEV_SNP.read_text()
    result = verify_sevsnp_report(
        hex_data, product="milan", vlek_cert=_VLEK_CERT,
    )

    assert result["valid"] is True, f"Verification failed: {result.get('error')}"
    assert result["error"] is None
