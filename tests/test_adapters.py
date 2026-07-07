import pytest

from src.core.taxonomy import NodeType, Platform, TCBStatus
from src.ingest.adapters.nitro import parse_nitro_attestation, verify_nitro_attestation
from src.ingest.adapters.sevsnp import parse_sevsnp_report, verify_sevsnp_report
from src.ingest.adapters.tdx import parse_tdx_quote, verify_tdx_quote


PLATFORMS = [
    pytest.param(
        Platform.IntelTDX,
        parse_tdx_quote,
        verify_tdx_quote,
        "tests/fixtures/tdx/sample_quote.hex",
        "tdx-quote-",
        {"measurement": "aa" * 48, "debug_disabled": True, "tcb_version": "03050000", "tcb_status": TCBStatus.UNKNOWN, "metadata[version]": 4},
        {},
        id="tdx",
    ),
    pytest.param(
        Platform.AMDSEVSNP,
        parse_sevsnp_report,
        verify_sevsnp_report,
        "tests/fixtures/sevsnp/sample_report.hex",
        "sevsnp-report-",
        {"measurement": "aa" * 48, "debug_disabled": True, "tcb_version": "3.5.1.128", "tcb_status": TCBStatus.UNKNOWN, "metadata[version]": 2},
        {"product": "genoa"},
        id="sevsnp",
    ),
    pytest.param(
        Platform.AWSNitro,
        parse_nitro_attestation,
        verify_nitro_attestation,
        "tests/fixtures/nitro/sample_attestation.hex",
        "nitro-attestation-",
        {"metadata[pcr0]": "aa" * 48},
        {},
        id="nitro",
    ),
]


def _check_attrs(node, expected):
    for key, value in expected.items():
        if "[" in key:
            attr, sub = key.split("[")
            sub = sub.rstrip("]")
            assert getattr(node, attr)[sub] == value
        else:
            assert getattr(node, key) == value


class TestParse:
    @pytest.mark.parametrize(
        ("platform", "parse_fn", "verify_fn", "fixture", "id_prefix", "expected", "verify_kw"),
        PLATFORMS,
    )
    def test_returns_evidence_node(self, platform, parse_fn, verify_fn, fixture, id_prefix, expected, verify_kw):
        with open(fixture) as f:
            hex_data = f.read()
        node = parse_fn(hex_data)
        assert node.node_type == NodeType.QUOTE
        assert node.platform == platform
        _check_attrs(node, expected)

    @pytest.mark.parametrize(
        ("platform", "parse_fn", "verify_fn", "fixture", "id_prefix", "expected", "verify_kw"),
        PLATFORMS,
    )
    def test_node_id_is_deterministic(self, platform, parse_fn, verify_fn, fixture, id_prefix, expected, verify_kw):
        with open(fixture) as f:
            hex_data = f.read()
        node1 = parse_fn(hex_data)
        node2 = parse_fn(hex_data)
        assert node1.node_id == node2.node_id
        assert node1.node_id.startswith(id_prefix)

    @pytest.mark.parametrize(
        ("platform", "parse_fn", "verify_fn", "fixture", "id_prefix", "expected", "verify_kw"),
        PLATFORMS,
    )
    def test_rejects_synthetic_fixture(self, platform, parse_fn, verify_fn, fixture, id_prefix, expected, verify_kw):
        with open(fixture) as f:
            hex_data = f.read()
        result = verify_fn(hex_data, **verify_kw)
        assert result["valid"] is False
        assert "error" in result
