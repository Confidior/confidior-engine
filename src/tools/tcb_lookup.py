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

# Intel PCS v4 TCB-info endpoints. Both require the platform's FMSPC (6 bytes
# hex), which comes from the PCK certificate chain of the quote.
# The TDX response carries a `tdxtcbcomponents` array that the SGX response does
# not, so the two are NOT interchangeable: a TDX quote's TEE_TCB_SVN must be
# compared against the TDX components. See _parse_intel_tcb_info.
INTEL_TCB_INFO_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb"
INTEL_TDX_TCB_INFO_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb"

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


def _tdx_components(level: dict) -> list[dict] | None:
    """Return a level's TDX component array, or None if the level has none."""
    tcb = level.get("tcb") or {}
    comps = tcb.get("tdxtcbcomponents")
    return comps if isinstance(comps, list) and comps else None


def _sgx_components(level: dict) -> list[dict] | None:
    """Return a level's SGX component array, or None if the level has none."""
    tcb = level.get("tcb") or {}
    comps = tcb.get("sgxtcbcomponents")
    return comps if isinstance(comps, list) and comps else None


def _parse_intel_tcb_info(data: dict, platform: Platform | None = None) -> str | None:
    """Extract the current TCB version from Intel PCS v4 TCB-info JSON.

    The response has tcbInfo.tcbLevels[], each with a tcb (component SVNs) and
    tcbStatus. The current TCB is the highest level whose status is UpToDate.
    Returns the first 4 component SVNs as a hex byte string, matching the
    engine's quoted tee_tcb_svn format (e.g. "0b010500").

    Component-array selection is platform-dependent and MUST NOT fall back
    across platforms. Intel's TDX TCB-info response contains BOTH
    `sgxtcbcomponents` and `tdxtcbcomponents`; the arrays carry different
    meanings and a TDX quote's TEE_TCB_SVN is compared byte-for-byte against
    `tdxtcbcomponents` only. Reading the SGX array for a TDX platform yields a
    confident but wrong version string, which is worse than UNKNOWN.

    Byte ordering for the TDX path is positional and 1:1 with no endianness
    conversion, per Intel's TDX DCAP Quoting Library API (TEE_TCB_SVN definition
    and the TCB-info evaluation section). The SGX PCK CPUSVN/PCESVN pre-checks
    and the tdxModuleIdentities refinement are deliberately NOT asserted here:
    neither is derivable from the quote alone at this call site, so claiming
    them would be a guess.
    """
    levels = (data.get("tcbInfo") or {}).get("tcbLevels") or []
    if not levels:
        return None

    def _svn_hex(comps: list[dict]) -> str:
        svns = [int(c.get("svn", 0)) for c in comps[:4]]
        return bytes(svns).hex()

    # Pick the selector for this platform. `None` means "unknown platform":
    # a TDX array present means this is a TDX response, so prefer it; an
    # SGX-only fixture keeps working for callers that pass no platform.
    if platform == Platform.IntelTDX:
        select = _tdx_components
    elif platform is None:
        select = lambda level: _tdx_components(level) or _sgx_components(level)  # noqa: E731
    else:
        select = _sgx_components

    scored: list[tuple[str, str]] = []
    for level in levels:
        comps = select(level)
        if not comps:
            # No components for this platform in this level: skip rather than
            # substitute the other platform's array.
            continue
        scored.append((_svn_hex(comps), str(level.get("tcbStatus") or "")))
    if not scored:
        return None

    uptodate = [s for s in scored if s[1] == "UpToDate"]
    best = uptodate or scored
    # Highest level = the one with the greatest component SVN tuple.
    best.sort(key=lambda pair: pair[0], reverse=True)
    return best[0][0]


def fetch_current_tcb(platform: Platform, fmspc: str | None = None) -> TCBReference | None:
    """Fetch the vendor's current TCB version for a platform.

    Intel TDX: queries the PCS v4 TCB-info endpoint with the platform's FMSPC.
    AMD SEV-SNP: returns None (no public current-TCB endpoint; the KDS VCEK
    encodes the quoted TCB, not the latest published one).

    Returns None on network failure or when the platform has no live source.
    The cache is keyed by (platform, fmspc) so a reference fetched for one
    platform config is never reused for another.
    """
    key = f"{platform.value}:{fmspc or ''}"
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
    """Query Intel PCS v4 TDX TCB-info and return the current TCB reference.

    Uses the /tdx/ endpoint, whose response carries the `tdxtcbcomponents`
    array a TDX quote's TEE_TCB_SVN is actually compared against. The /sgx/
    endpoint's component array describes a different set of fields.
    """
    url = f"{INTEL_TDX_TCB_INFO_URL}?fmspc={fmspc}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None
    version = _parse_intel_tcb_info(data, platform=Platform.IntelTDX)
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


def main() -> int:
    """CLI entry: fetch the current TCB reference for a platform.

    Usage: uv run python -m src.tools.tcb_lookup --platform intel --fmspc 50806F000000
    """
    import argparse

    parser = argparse.ArgumentParser(description="Fetch the current TCB reference for a platform")
    parser.add_argument("--platform", required=True, choices=[p.value for p in Platform])
    parser.add_argument("--fmspc", help="Intel FMSPC (6 bytes hex) for Intel platforms")
    args = parser.parse_args()

    platform = Platform(args.platform)
    ref = fetch_current_tcb(platform, args.fmspc)
    if ref is None:
        print(f"platform={args.platform} status=UNKNOWN (no reference available; honest fallback)")
        return 1
    print(f"platform={ref.platform} version={ref.version} status={ref.status}")
    print(f"fetched_at={ref.fetched_at}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
