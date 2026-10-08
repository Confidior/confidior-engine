"""Live TCB lookup tests (mocked HTTP)."""
import json
from pathlib import Path
from unittest import mock

from src.core.taxonomy import Platform
from src.tools.tcb_lookup import (
    _parse_intel_tcb_info,
    clear_cache,
    fetch_current_tcb,
)


def _tcb_info_json(levels):
    return {"tcbInfo": {"tcbLevels": levels}}


def _level(svns, status):
    return {
        "tcb": {"sgxtcbcomponents": [{"svn": s} for s in svns]},
        "tcbStatus": status,
    }


def test_parse_intel_tcb_info_returns_uptodate_level():
    data = _tcb_info_json(
        [
            _level([1, 1, 2, 0], "OutOfDate"),
            _level([11, 1, 5, 0], "UpToDate"),
        ]
    )
    assert _parse_intel_tcb_info(data) == "0b010500"


def test_parse_intel_tcb_info_falls_back_to_highest():
    data = _tcb_info_json([_level([1, 1, 2, 0], "OutOfDate")])
    assert _parse_intel_tcb_info(data) == "01010200"


def test_parse_intel_tcb_info_empty_returns_none():
    assert _parse_intel_tcb_info({}) is None
    assert _parse_intel_tcb_info({"tcbInfo": {"tcbLevels": []}}) is None


def test_fetch_intel_tcb_success():
    clear_cache()
    payload = json.dumps(
        _tcb_info_json([_tdx_level([5, 5, 2, 2], [11, 1, 5, 0], "UpToDate")])
    ).encode()
    with mock.patch(
        "urllib.request.urlopen",
        return_value=mock.MagicMock(
            __enter__=lambda s: s,
            read=lambda: payload,
        ),
    ):
        ref = fetch_current_tcb(Platform.IntelTDX, fmspc="50806f000000")
    assert ref is not None
    assert ref.version == "0b010500"
    assert ref.status == "current"


def test_fetch_intel_tcb_network_failure_returns_none():
    clear_cache()
    with mock.patch(
        "urllib.request.urlopen", side_effect=Exception("network down")
    ):
        ref = fetch_current_tcb(Platform.IntelTDX, fmspc="50806f000000")
    assert ref is None


def test_fetch_intel_tcb_requires_fmspc():
    clear_cache()
    assert fetch_current_tcb(Platform.IntelTDX) is None


def test_fetch_amd_returns_none_no_public_endpoint():
    clear_cache()
    assert fetch_current_tcb(Platform.AMDSEVSNP) is None


def test_cache_returns_cached_reference():
    clear_cache()
    payload = json.dumps(
        _tcb_info_json([_tdx_level([5, 5, 2, 2], [11, 1, 5, 0], "UpToDate")])
    ).encode()
    with mock.patch(
        "urllib.request.urlopen",
        return_value=mock.MagicMock(
            __enter__=lambda s: s,
            read=lambda: payload,
        ),
    ):
        ref1 = fetch_current_tcb(Platform.IntelTDX, fmspc="50806f000000")
    # Second call should hit the cache, not the network.
    with mock.patch(
        "urllib.request.urlopen", side_effect=AssertionError("should not hit network")
    ):
        ref2 = fetch_current_tcb(Platform.IntelTDX, fmspc="50806f000000")
    assert ref1 == ref2


def test_fmspc_reaches_live_lookup_via_verdict(tmp_path):
    """The fmspc passed to the verdict reaches the live lookup (mocked)."""
    from src.core.risk import _resolve_tcb_statuses
    from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType, TCBStatus

    clear_cache()
    payload = json.dumps(
        _tcb_info_json(
            [
                _tdx_level(
                    [5, 5, 2, 2],
                    [11, 1, 5, 0],
                    "UpToDate",
                )
            ]
        )
    ).encode()

    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode(
            node_id="q1",
            node_type=NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="aa" * 48,
            tcb_version="0b010500",
        )
    )
    with mock.patch(
        "urllib.request.urlopen",
        return_value=mock.MagicMock(
            __enter__=lambda s: s,
            read=lambda: payload,
        ),
    ):
        resolutions = _resolve_tcb_statuses(graph, tcb_fmspc="50806f000000")
    assert resolutions[Platform.IntelTDX.value] == TCBStatus.CURRENT


def test_cli_entry_exists_and_handles_unknown():
    """The module must be runnable as a CLI (review finding 2026-08-25:
    `python -m src.tools.tcb_lookup` silently did nothing — no main entry)."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "src.tools.tcb_lookup", "--platform", "AMD-SEV-SNP"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert proc.returncode == 1  # honest UNKNOWN fallback, not a crash
    assert "UNKNOWN" in proc.stdout


# --- TDX component-array selection (regression, verified live 2026-10-09) -----
#
# Intel's TDX TCB-info response contains BOTH sgxtcbcomponents and
# tdxtcbcomponents. The old parser took them in that textual order, so a TDX
# platform silently read the SGX array and produced a confident wrong version.
# Captured live: https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=20A06F000000
#   sgxtcbcomponents[:4] = [5, 5, 2, 2]       -> "05050202"  (wrong)
#   tdxtcbcomponents[:6] = [5, 0, 5, 0, 0, 0] -> "0500050000" (used by TDX)
# The RedPill quote's TEE_TCB_SVN is 0b010500000000000000000000000000.


def _tdx_level(sgx_svns, tdx_svns, status):
    tcb = {}
    if sgx_svns is not None:
        tcb["sgxtcbcomponents"] = [{"svn": s} for s in sgx_svns]
    if tdx_svns is not None:
        tcb["tdxtcbcomponents"] = [{"svn": s} for s in tdx_svns]
    return {"tcb": tcb, "tcbStatus": status}


def test_tdx_platform_reads_tdx_components_not_sgx():
    """The regression: both arrays present, TDX must win."""
    data = _tcb_info_json(
        [_tdx_level([5, 5, 2, 2], [5, 0, 5, 0, 0, 0], "UpToDate")]
    )
    assert _parse_intel_tcb_info(data, platform=Platform.IntelTDX) == "05000500"
    # Never the SGX array.
    assert _parse_intel_tcb_info(data, platform=Platform.IntelTDX) != "05050202"


def test_tdx_platform_without_tdx_components_returns_none_not_sgx():
    """No TDX array means no TDX reference. Substituting SGX would be a
    confident fabrication, so the honest answer is None."""
    data = _tcb_info_json([_tdx_level([5, 5, 2, 2], None, "UpToDate")])
    assert _parse_intel_tcb_info(data, platform=Platform.IntelTDX) is None


def test_sgx_platform_still_reads_sgx_components():
    data = _tcb_info_json([_tdx_level([5, 5, 2, 2], [5, 0, 5], "UpToDate")])
    assert _parse_intel_tcb_info(data, platform=Platform.AMDSEVSNP) == "05050202"


def test_unknown_platform_prefers_tdx_when_present():
    """A response carrying a TDX array is a TDX response."""
    data = _tcb_info_json(
        [_tdx_level([5, 5, 2, 2], [5, 0, 5, 0, 0, 0], "UpToDate")]
    )
    assert _parse_intel_tcb_info(data) == "05000500"


def test_tdx_level_without_components_is_skipped_not_crashed():
    levels = [
        _tdx_level(None, None, "UpToDate"),
        _tdx_level([5, 5, 2, 2], [5, 0, 5, 0, 0, 0], "OutOfDate"),
    ]
    assert _parse_intel_tcb_info(_tcb_info_json(levels), platform=Platform.IntelTDX) == "05000500"


def test_tdx_uptodate_level_beats_higher_outofdate_level():
    """A numerically higher OutOfDate level must not outrank an UpToDate one."""
    levels = [
        _tdx_level([5, 5, 2, 2], [9, 9, 9, 9], "OutOfDate"),
        _tdx_level([5, 5, 2, 2], [5, 0, 5, 0, 0, 0], "UpToDate"),
    ]
    assert _parse_intel_tcb_info(_tcb_info_json(levels), platform=Platform.IntelTDX) == "05000500"


def test_fetch_uses_tdx_endpoint_and_parses_tdx_components():
    clear_cache()
    payload = json.dumps(
        _tcb_info_json(
            [_tdx_level([5, 5, 2, 2], [5, 0, 5, 0, 0, 0], "UpToDate")]
        )
    ).encode()
    captured = {}

    def _fake_urlopen(url, timeout=None):
        captured["url"] = url
        return mock.MagicMock(__enter__=lambda s: s, read=lambda: payload)

    with mock.patch("urllib.request.urlopen", _fake_urlopen):
        ref = fetch_current_tcb(Platform.IntelTDX, fmspc="20a06f000000")
    assert ref is not None
    assert ref.version == "05000500"
    assert "/tdx/" in captured["url"]
