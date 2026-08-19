"""Live TCB lookup tests (mocked HTTP)."""
import json
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
