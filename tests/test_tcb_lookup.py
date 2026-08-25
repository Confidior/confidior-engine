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
        _tcb_info_json([_level([11, 1, 5, 0], "UpToDate")])
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
        _tcb_info_json([_level([11, 1, 5, 0], "UpToDate")])
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
        {
            "tcbInfo": {
                "tcbLevels": [
                    {
                        "tcb": {
                            "sgxtcbcomponents": [
                                {"svn": 11}, {"svn": 1}, {"svn": 5}, {"svn": 0}
                            ]
                        },
                        "tcbStatus": "UpToDate",
                    }
                ]
            }
        }
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
