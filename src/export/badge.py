from __future__ import annotations

import hashlib

from src.core.taxonomy import AssuranceEvaluation, AssuranceLevel

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

_BADGE_WIDTH = 200
_BADGE_HEIGHT = 20
_LABEL_X = 5
_LABEL_WIDTH = 90
_VALUE_X = 95
_VALUE_WIDTH = 105


def _compute_commitment(bundle_id: str, level: int, signature_hex: str) -> str:
    commitment_input = f"{bundle_id}:{level}:{signature_hex}"
    return hashlib.sha256(commitment_input.encode()).hexdigest()[:16]


def generate_badge_svg(
    assurance: AssuranceEvaluation,
    bundle_id: str = "",
    signature_hex: str = "",
) -> str:
    level_num = assurance.level.value
    color = _LEVEL_COLORS.get(level_num, "#999999")
    label = f"Level {level_num}"
    name = _LEVEL_NAMES.get(level_num, "Unknown")

    title = f"Confidior {label} | {name}"
    if bundle_id:
        title += f" | {bundle_id}"

    commitment = ""
    if bundle_id and signature_hex:
        commitment = _compute_commitment(bundle_id, level_num, signature_hex)

    commitment_attr = ""
    if commitment:
        commitment_attr = f' data-commitment="{commitment}" data-bundle-id="{bundle_id}"'

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_BADGE_WIDTH}" height="{_BADGE_HEIGHT}"{commitment_attr}>'
        f'<title>{title}</title>'
        f'<rect width="{_BADGE_WIDTH}" height="{_BADGE_HEIGHT}" rx="3" fill="#555"/>'
        f'<rect x="{_LABEL_WIDTH}" width="{_VALUE_WIDTH}" height="{_BADGE_HEIGHT}" rx="3" fill="{color}"/>'
        f'<text x="{_LABEL_X + 45}" y="14" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        f'font-size="11" fill="#fff" text-anchor="middle">Confidior</text>'
        f'<text x="{_VALUE_X + 52}" y="14" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" '
        f'font-size="11" fill="#fff" text-anchor="middle">{label}</text>'
        f"</svg>"
    )


def verify_badge(commitment: str, bundle_id: str, level: int, signature_hex: str) -> bool:
    expected = _compute_commitment(bundle_id, level, signature_hex)
    return commitment == expected
