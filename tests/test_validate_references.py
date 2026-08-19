"""Tests for the curated-reference validation script (mocked HTTP)."""
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path("scripts").resolve()))

from validate_references import (
    validate_amd_bulletin,
    validate_amd_schema,
    validate_attack_sources,
)


def _amd_html():
    return (
        "<html>"
        "<tr><td>Milan</td><td>TCB[SNP]&gt;=0x1D mitigation bit = 4</td></tr>"
        "<tr><td>Genoa</td><td>TCB[SNP]&gt;=0x1C</td></tr>"
        "<tr><td>Turin</td><td>TCB[SNP]&gt;=0x5</td></tr>"
        "</html>"
    )


# Every curated advisory URL maps to the same mock page so per-record
# validation finds all thresholds.
_AMD_URLS = {
    "https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3034.html": _amd_html(),
    "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3030.html": _amd_html(),
    "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3011.html": (
        "<html>TCB[SNP] &gt; 0x16</html>"
    ),
    "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3019.html": (
        "<html>TCB[SNP] = 0x18</html>"
    ),
}


def _patch_fetch_map():
    return mock.patch(
        "validate_references._fetch",
        side_effect=lambda url: _AMD_URLS.get(url, _amd_html()),
    )


def test_amd_schema_valid():
    assert validate_amd_schema() == []


def test_amd_bulletin_matches_curated_values():
    with _patch_fetch_map():
        assert validate_amd_bulletin() == []


def test_amd_bulletin_detects_stale_value():
    # Bulletin says 0x1A for Milan but the curated value is 0x1D -> the value
    # check fails (0x1D not found anywhere in the mocked bulletins).
    stale = {
        "https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3034.html": (
            "<html><tr><td>Milan</td><td>TCB[SNP]&gt;=0x1A</td></tr>"
            "<tr><td>Genoa</td><td>TCB[SNP]&gt;=0x1C</td></tr>"
            "<tr><td>Turin</td><td>TCB[SNP]&gt;=0x5</td></tr></html>"
        ),
        "https://www.amd.com/en/piv": "",
    }
    with mock.patch(
        "validate_references._fetch", side_effect=lambda url: stale.get(url, "")
    ):
        errors = validate_amd_bulletin()
    assert any("Milan" in e and "not found" in e for e in errors)


def test_amd_bulletin_detects_missing_threshold():
    # Turin's threshold removed from the bulletin page -> failure.
    missing = {
        "https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3034.html": (
            "<html><tr><td>Milan</td><td>TCB[SNP]&gt;=0x1D</td></tr>"
            "<tr><td>Genoa</td><td>TCB[SNP]&gt;=0x1C</td></tr></html>"
        ),
        "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3030.html": (
            "<html></html>"
        ),
        "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3011.html": (
            "<html></html>"
        ),
        "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3019.html": (
            "<html></html>"
        ),
    }
    with mock.patch(
        "validate_references._fetch", side_effect=lambda url: missing.get(url, "")
    ):
        errors = validate_amd_bulletin()
    assert any("Turin" in e and "not found" in e for e in errors)


def test_amd_bulletin_network_failure_reported():
    with mock.patch("validate_references._fetch", return_value=None):
        errors = validate_amd_bulletin()
    assert any("cannot fetch" in e for e in errors)


def test_attack_sources_schema_offline():
    assert validate_attack_sources(offline=True) == []


def test_attack_sources_reachability():
    with mock.patch("validate_references._fetch", return_value="<html>ok</html>"):
        assert validate_attack_sources() == []


def test_attack_sources_unreachable_detected():
    with mock.patch("validate_references._fetch", return_value=None):
        errors = validate_attack_sources()
    # At least one source should fail when nothing is reachable.
    assert len(errors) >= 1


def test_pattern_matches_amd_html():
    import validate_references

    found = validate_references._amd_thresholds(_amd_html())
    assert set(found) == {0x1D, 0x1C, 0x5}


def test_pattern_handles_strict_and_equality():
    from validate_references import _amd_thresholds

    # > 0x16 -> effective 0x17; = 0x18 -> 0x18
    assert 0x17 in _amd_thresholds("<html>TCB[SNP] &gt; 0x16</html>")
    assert 0x18 in _amd_thresholds("<html>TCB[SNP] = 0x18</html>")
