from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _dedup_anchors(text: str) -> str:
    seen: dict[str, int] = {}
    def _replace_anchor(match):
        full = match.group(0)
        anchor_name = match.group(1)
        if anchor_name in seen:
            seen[anchor_name] += 1
            return full.replace(f"&{anchor_name}", f"&{anchor_name}_{seen[anchor_name]}")
        seen[anchor_name] = 0
        return full

    return re.sub(r"&([A-Za-z_][A-Za-z0-9_]*)", _replace_anchor, text)


@dataclass(frozen=True)
class C5Subcriterion:
    identifier: str
    criterion: str


@dataclass(frozen=True)
class C5Criterion:
    identifier: str
    name: str
    basic: list[C5Subcriterion] = field(default_factory=list)
    additional_sharpen: list[C5Subcriterion] | None = None
    additional_complement: list[C5Subcriterion] | None = None
    information: list[dict[str, Any]] = field(default_factory=list)
    corresponding: str | None = None
    condition: str | None = None
    hint: str | None = None


@dataclass
class C5ControlFamily:
    family_id: str
    criteria: list[C5Criterion] = field(default_factory=list)


def _parse_subcriteria(raw: list[dict] | None) -> list[C5Subcriterion]:
    if not raw:
        return []
    return [
        C5Subcriterion(
            identifier=item.get("identifier", ""),
            criterion=item.get("criterion", ""),
        )
        for item in raw
    ]


def _parse_criterion(raw: dict[str, Any]) -> C5Criterion:
    ident = raw.get("identifier") or raw.get("id", "")
    return C5Criterion(
        identifier=str(ident),
        name=raw.get("name", ""),
        basic=_parse_subcriteria(raw.get("basic")),
        additional_sharpen=_parse_subcriteria(raw.get("additional_sharpen")),
        additional_complement=_parse_subcriteria(raw.get("additional_complement")),
        information=raw.get("information") or [],
        corresponding=raw.get("corresponding"),
        condition=raw.get("condition"),
        hint=raw.get("hint"),
    )


def load_c5_family(yaml_path: str | Path) -> C5ControlFamily:
    with open(yaml_path) as f:
        text = f.read()
    text = _dedup_anchors(text)
    raw_list: list[dict[str, Any]] = yaml.safe_load(text)

    if not raw_list:
        return C5ControlFamily(family_id=Path(yaml_path).stem)

    criteria = [_parse_criterion(item) for item in raw_list]
    family_id = Path(yaml_path).stem
    return C5ControlFamily(family_id=family_id, criteria=criteria)


def load_all_c5_families(c5_dir: str | Path) -> list[C5ControlFamily]:
    c5_dir = Path(c5_dir)
    families = []
    for yml in sorted(c5_dir.glob("*.yml")):
        families.append(load_c5_family(yml))
    return families


def find_criterion(families: list[C5ControlFamily], criterion_id: str) -> C5Criterion | None:
    for family in families:
        for criterion in family.criteria:
            if criterion.identifier == criterion_id:
                return criterion
    return None
