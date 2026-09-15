"""SVG badge generator for assurance level visualization."""

from __future__ import annotations

import hashlib
import html
import json

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
    """Generate an SVG badge showing attestation-specific dimensions and metadata.

    Card-style layout matching the confidior.com badge aesthetic: the grade,
    the score, and the dimension rows, with the data-commitment attributes
    preserved for verification.
    """
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
        data_attrs += (
            f' data-commitment="{commitment}" data-bundle-id="{bundle_id}" data-level="{level_num}"'
        )
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
        data_attrs += f' data-score-profile="{assurance.score.profile}"'
        if assurance.score.platform_score is not None:
            data_attrs += (
                f' data-platform-score="{assurance.score.platform_score}"'
                f' data-quote-score="{assurance.score.quote_score}"'
            )
        if assurance.score.evidence_class is not None:
            data_attrs += f' data-evidence-class="{assurance.score.evidence_class.value}"'
        if assurance.residual_risk:
            data_attrs += f' data-risk="{assurance.residual_risk.value}"'
    if dims:
        dim_json = json.dumps(dims, sort_keys=True, ensure_ascii=False)
        data_attrs += f' data-dimensions="{html.escape(dim_json, quote=True)}"'

    # ---- visual layout (card style, matching confidior.com) ----
    W = 320
    bg = "#0f1117"
    panel = "#161822"
    text = "#e5e7eb"
    muted = "#9ca3af"
    faint = "#6b7280"
    mono = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

    grade = assurance.score.grade if assurance.score else "—"
    score = assurance.score.total if assurance.score else None
    grade_color = _RED if grade in ("F", "D") else (_AMBER if grade in ("C", "B") else _GREEN)
    risk = assurance.residual_risk.value if assurance.residual_risk else ""

    def dim_value_color(key: str, val: str) -> str:
        if key in ("measure", "measurement"):
            return _GREEN if val in ("verified", "match", "✓") else _RED
        if key == "freshness":
            return _GREEN if val == "FRESH" else (_AMBER if val == "AGING" else _RED)
        if key == "debug":
            return _GREEN if val == "OFF" else _RED
        if key == "attacks":
            return _GREEN if val == "none applied" else _RED
        if key == "evidence":
            # Only the strongest classes (computed golden, runtime-anchored)
            # read as good; weaker provenance is real but not strong.
            return _GREEN if val in ("computed-golden", "runtime-anchored") else _AMBER
        if key == "split":
            return muted
        if key == "provenance":
            return _RED if val == "absent" else _GREEN
        if key == "score":
            return _RED if grade in ("F", "D") else (_AMBER if grade in ("C", "B") else _GREEN)
        return text

    def dim_value_short(key: str, val: str) -> str:
        if key == "freshness":
            # "STALE (120m / 30m TTL)" → "STALE (120m/30m TTL)"
            return val.replace(" / ", "/")
        if key == "measure":
            return "✓ match" if val in ("verified", "match") else "✗ mismatch"
        return val

    # dims in the confidior.com order: platform, measure, split, evidence,
    # attacks, captured, debug, provenance, score
    dim_order = (
        "platform", "measure", "measurement", "split", "evidence", "attacks",
        "captured", "freshness", "debug", "tcb", "provenance", "score",
    )
    rows: list[tuple[str, str, str]] = []
    for key in dim_order:
        val = dims.get(key)
        if val:
            rows.append((key, dim_value_short(key, val), dim_value_color(key, val)))

    H = 34 + 66 + 18 * len(rows) + 26  # header + grade area + rows + footer

    # header
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{W}" height="{H}"{data_attrs}>'
        f"<title>{title}</title>"
        f'<rect width="{W}" height="{H}" rx="12" fill="{bg}"/>'
        f'<rect width="{W}" height="34" rx="12" fill="{panel}"/>'
        f'<rect y="30" width="{W}" height="4" fill="{panel}"/>'
        f'<text x="16" y="22" font-family="{mono}" font-size="12" '
        f'font-weight="700" fill="{text}">Confidior</text>'
    )
    # header chips: L{level} + risk
    chip_x = W - 16
    chip_w = 0
    other_color = "#450a0a" if risk == "CRITICAL" else "#422006"
    for chip_text, chip_color in (
        (f"L{level_num}", "#172554"),
        (risk, other_color),
    ):
        if not chip_text:
            continue
        chip_w = int(8 + len(chip_text) * 6.5 + 8)
        chip_x -= chip_w
        risk_color = _RED if risk == "CRITICAL" else _AMBER
        svg += (
            f'<rect x="{chip_x}" y="10" width="{chip_w}" height="16" '
            f'rx="8" fill="{chip_color}"/>'
            f'<text x="{chip_x + chip_w / 2}" y="21" '
            f'font-family="{mono}" font-size="9" fill="{risk_color}" '
            f'text-anchor="middle">{chip_text}</text>'
        )
        chip_x -= 6
    # grade + score
    svg += (
        f'<text x="16" y="88" font-family="{mono}" font-size="52" '
        f'font-weight="750" fill="{grade_color}">{grade}</text>'
    )
    if score is not None:
        svg += (
            f'<text x="78" y="88" font-family="{mono}" font-size="20" '
            f'fill="{muted}">{score}'
            f'<tspan font-size="13" fill="{faint}">/100</tspan></text>'
        )
    # dimension rows
    y = 116
    for key, val, vcolor in rows:
        svg += (
            f'<text x="16" y="{y}" font-family="{mono}" font-size="11" '
            f'fill="{faint}">{key}</text>'
            f'<text x="{W - 16}" y="{y}" font-family="{mono}" font-size="11" '
            f'fill="{vcolor}" text-anchor="end">{val}</text>'
        )
        y += 18
    # footer
    if bundle_id:
        svg += (
            f'<text x="16" y="{H - 8}" font-family="{mono}" font-size="9" '
            f'fill="{faint}">{bundle_id}</text>'
        )
    svg += "</svg>"
    return svg


def verify_badge(
    commitment: str,
    bundle_id: str,
    level: int,
    signature_hex: str,
    dimensions: dict[str, str] | None = None,
) -> bool:
    expected = compute_badge_commitment(bundle_id, level, signature_hex, dimensions)
    return commitment == expected


def extract_badge_attributes(svg: str) -> dict[str, object]:
    """Parse data-* attributes from a generated badge SVG.

    Returns a dict with: commitment, bundle_id, level (if present), score, grade,
    score_profile, dimensions dict, plus raw boolean/individual attributes.
    """
    attrs: dict[str, object] = {}
    patterns = {
        "commitment": r'data-commitment="([^"]+)"',
        "bundle_id": r'data-bundle-id="([^"]+)"',
        "level": r'data-level="(\d+)"',
        "measurement_verified": r'data-measurement-verified="(true|false)"',
        "freshness": r'data-freshness="([^"]+)"',
        "debug_disabled": r'data-debug-disabled="(true|false)"',
        "tcb_version": r'data-tcb-version="([^"]+)"',
        "score": r'data-score="(\d+)"',
        "grade": r'data-grade="([^"]+)"',
        "score_profile": r'data-score-profile="([^"]+)"',
        "dimensions": r'data-dimensions="([^"]*)"',
    }
    import re

    for key, pattern in patterns.items():
        match = re.search(pattern, svg)
        if match:
            value = match.group(1)
            if key in ("measurement_verified", "debug_disabled"):
                attrs[key] = value == "true"
            elif key in ("level", "score"):
                attrs[key] = int(value)
            elif key == "dimensions":
                # html.unescape is needed because we escaped quotes during generation.
                import html

                raw = html.unescape(value)
                attrs[key] = json.loads(raw) if raw else {}
            else:
                attrs[key] = value
    return attrs
