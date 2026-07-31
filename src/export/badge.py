"""SVG badge generator for assurance level visualization."""

from __future__ import annotations

import hashlib

from src.core.taxonomy import AssuranceEvaluation

_LEVEL_COLORS = {
    0: "#999999",
    1: "#df3c30",
    2: "#df3c30",
    3: "#e88a2a",
    4: "#4dc729",
    5: "#007ec6",
}

_LEVEL_NAMES = {
    0: "None",
    1: "Config-Verified",
    2: "Hardware-Attested",
    3: "Operational Assurance",
    4: "Distributed Trust",
    5: "Cryptographic Privacy",
}

_GREEN = "#4dc729"
_RED = "#df3c30"
_AMBER = "#f59e0b"
_BLUE = "#3b82f6"
_NEUTRAL = "#999999"

_BADGE_WIDTH = 220
_BADGE_HEIGHT = 20
_LABEL_X = 5
_LABEL_WIDTH = 100
_VALUE_X = 105
_VALUE_WIDTH = 115


def compute_badge_commitment(
    bundle_id: str,
    level: int,
    signature_hex: str,
    dimensions: dict[str, str] | None = None,
) -> str:
    parts = [bundle_id, str(level), signature_hex]
    if dimensions:
        for k in sorted(dimensions):
            parts.append(f"{k}={dimensions[k]}")
    commitment_input = ":".join(parts)
    return hashlib.sha256(commitment_input.encode()).hexdigest()[:16]


def _choose_headline(dimensions: dict[str, str] | None, level: int = 2) -> tuple[str, str]:
    if not dimensions:
        return f"Level {level}", _LEVEL_COLORS.get(level, _NEUTRAL)
    meas = dimensions.get("measurement", "")
    if meas:
        if meas == "verified":
            return "measure=✓", _GREEN
        return "measure=✗", _RED
    fresh = dimensions.get("freshness", "")
    if fresh == "FRESH":
        return "FRESH", _GREEN
    if fresh == "AGING":
        return "AGING", _AMBER
    if fresh == "STALE":
        return "STALE", _RED
    return f"Level {level}", _LEVEL_COLORS.get(level, _NEUTRAL)


def _build_dimension_text(dimensions: dict[str, str] | None, level: int, score=None) -> str:
    parts = [f"L{level}"]
    if score:
        parts.append(f"{score.total}/100")
    if dimensions:
        for dim in ("measurement", "freshness", "debug", "tcb", "provenance"):
            val = dimensions.get(dim)
            if val:
                if dim == "measurement":
                    parts.append(f"measure={'✓' if val == 'verified' else '✗'}")
                elif dim in ("freshness", "tcb"):
                    short = val.split("(")[0].strip()
                    if short != val:
                        parts.append(f"{dim}={short}")
                    else:
                        parts.append(f"{dim}={val}")
                elif dim == "debug":
                    parts.append(f"debug={'OFF' if val == 'OFF' else 'ON'}")
                else:
                    parts.append(f"{dim}={val}")
    return " | ".join(parts)


def generate_badge_svg(
    assurance: AssuranceEvaluation,
    bundle_id: str = "",
    signature_hex: str = "",
    measurement_verified: bool | None = None,
    freshness: str | None = None,
    debug_disabled: bool | None = None,
    tcb_version: str | None = None,
    dimensions: dict[str, str] | None = None,
) -> str:
    """Generate an SVG badge showing attestation-specific dimensions and metadata."""
    level_num = assurance.level.value

    dims = dimensions or {}
    if measurement_verified is not None and "measurement" not in dims:
        dims["measurement"] = "verified" if measurement_verified else "mismatch"
    if freshness and "freshness" not in dims:
        dims["freshness"] = freshness
    if debug_disabled is not None and "debug" not in dims:
        dims["debug"] = "OFF" if debug_disabled else "ON"
    if tcb_version and "tcb" not in dims:
        dims["tcb"] = tcb_version

    label, color = _choose_headline(dims, level_num)

    title = f"Confidior | {label}"
    if bundle_id:
        title += f" | {bundle_id}"

    commitment = ""
    if bundle_id and signature_hex:
        commitment = compute_badge_commitment(bundle_id, level_num, signature_hex, dims)

    data_attrs = ""
    if commitment:
        data_attrs += f' data-commitment="{commitment}" data-bundle-id="{bundle_id}"'
    if dims.get("measurement"):
        meas_bool = dims["measurement"] == "verified"
        data_attrs += f' data-measurement-verified="{str(meas_bool).lower()}"'
    if dims.get("freshness"):
        data_attrs += f' data-freshness="{dims["freshness"]}"'
    if dims.get("debug"):
        debug_val = dims["debug"] == "OFF"
        data_attrs += f' data-debug-disabled="{str(debug_val).lower()}"'
    if dims.get("tcb"):
        data_attrs += f' data-tcb-version="{dims["tcb"]}"'
    if assurance.score:
        data_attrs += f' data-score="{assurance.score.total}" data-grade="{assurance.score.grade}"'

    dim_text = _build_dimension_text(dims, level_num, assurance.score)
    badge_height = _BADGE_HEIGHT + 16

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_BADGE_WIDTH}" height="{badge_height}"{data_attrs}>'
        f'<title>{title}</title>'
        f'<rect width="{_BADGE_WIDTH}" height="{_BADGE_HEIGHT}" rx="3" fill="#555"/>'
        f'<rect x="{_LABEL_WIDTH}" width="{_VALUE_WIDTH}" height="{_BADGE_HEIGHT}" rx="3" fill="{color}"/>'
        f'<text x="{_LABEL_X + 50}" y="14" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        f'font-size="11" fill="#fff" text-anchor="middle">Confidior</text>'
        f'<text x="{_VALUE_X + 57}" y="14" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        f'font-size="11" fill="#fff" text-anchor="middle">{label}</text>'
    )
    svg += (
        f'<text x="{_BADGE_WIDTH // 2}" y="36" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        f'font-size="10" fill="#bbb" text-anchor="middle">{dim_text}</text>'
    )
    svg += "</svg>"
    return svg


def verify_badge(commitment: str, bundle_id: str, level: int, signature_hex: str) -> bool:
    expected = compute_badge_commitment(bundle_id, level, signature_hex)
    return commitment == expected