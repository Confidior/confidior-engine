"""Live TCB lookup: fetch the vendor's current TCB version per platform.

Intel TDX has a public TCB-info API (PCS v4). AMD SEV-SNP does not expose a
public "current TCB" endpoint: the KDS VCEK cert encodes the *quoted* TCB's
reference values, not the latest published TCB. So the live lookup covers Intel
TDX; AMD falls back to the local reference DB or honest UNKNOWN.

Results are cached in memory with a TTL so verification does not hit the
vendor API on every call. Network failure returns None (honest fallback, never
a fabricated reference).
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass

from src.core.taxonomy import Platform

# Intel PCS v4 TCB-info endpoint. Requires the platform's FMSPC (6 bytes hex),
# which comes from the PCK certificate chain of the quote.
INTEL_TCB_INFO_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb"

# How long a fetched TCB reference stays valid before re-fetching.
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h


@dataclass(frozen=True)
class TCBReference:
    """A fetched current-TCB reference for a platform."""

    platform: str
    version: str
    status: str
    fetched_at: float


_cache: dict[str, tuple[float, TCBReference | None]] = {}


def _parse_intel_tcb_info(data: dict) -> str | None:
    """Extract the current TCB version from Intel PCS v4 TCB-info JSON.

    The response has tcbInfo.tcbLevels[], each with a tcb (component SVNs) and
    tcbStatus. The current TCB is the highest level whose status is UpToDate.
    Returns the first 4 component SVNs as a hex byte string, matching the
    engine's quoted tee_tcb_svn format (e.g. "0b010500").
    """
    levels = (data.get("tcbInfo") or {}).get("tcbLevels") or []
    if not levels:
        return None
    # Prefer the highest UpToDate level; fall back to the highest level overall.
    def _svn_hex(level: dict) -> str:
        tcb = level.get("tcb") or {}
        comps = tcb.get("sgxtcbcomponents") or tcb.get("tdxtcbcomponents") or []
        svns = [int(c.get("svn", 0)) for c in comps[:4]]
        return bytes(svns).hex()

    uptodate = [level for level in levels if level.get("tcbStatus") == "UpToDate"]
    best = uptodate or levels
    # Highest level = the one with the greatest component SVN tuple.
    best.sort(key=lambda level: _svn_hex(level), reverse=True)
    return _svn_hex(best[0])


def fetch_current_tcb(platform: Platform, fmspc: str | None = None) -> TCBReference | None:
    """Fetch the vendor's current TCB version for a platform.

    Intel TDX: queries the PCS v4 TCB-info endpoint with the platform's FMSPC.
    AMD SEV-SNP: returns None (no public current-TCB endpoint; the KDS VCEK
    encodes the quoted TCB, not the latest published one).

    Returns None on network failure or when the platform has no live source.
    """
    key = platform.value
    now = time.time()
    if key in _cache:
        fetched_at, ref = _cache[key]
        if now - fetched_at < CACHE_TTL_SECONDS:
            return ref

    if platform == Platform.IntelTDX:
        if not fmspc:
            _cache[key] = (now, None)
            return None
        ref = _fetch_intel_tcb(fmspc)
        _cache[key] = (now, ref)
        return ref

    # AMD SEV-SNP and other platforms: no public current-TCB endpoint.
    _cache[key] = (now, None)
    return None


def _fetch_intel_tcb(fmspc: str) -> TCBReference | None:
    """Query Intel PCS v4 TCB-info and return the current TCB reference."""
    url = f"{INTEL_TCB_INFO_URL}?fmspc={fmspc}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None
    version = _parse_intel_tcb_info(data)
    if not version:
        return None
    return TCBReference(
        platform=Platform.IntelTDX.value,
        version=version,
        status="current",
        fetched_at=time.time(),
    )


def clear_cache() -> None:
    """Clear the in-memory TCB reference cache (used by tests)."""
    _cache.clear()
