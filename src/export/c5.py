"""C5:2026 compliance mapping and report generation."""

from __future__ import annotations

import sys
from pathlib import Path

from src.core.taxonomy import (
    ComplianceMapping,
    ComplianceStatus,
    ControlFamily,
    EvidenceGraph,
    NodeType,
)
from src.ingest.raw.c5 import (
    C5Subcriterion,
    load_all_c5_families,
)

_FAM_EVALUATION_TYPE = {
    "OPS": "technical",
    "CRY": "technical",
    "IAM": "technical",
    "OIS": "technical",
    "COS": "technical",
    "DEV": "technical",
    "INQ": "technical",
    "SIM": "technical",
    "AM": "organizational",
    "BCM": "organizational",
    "COM": "organizational",
    "GC": "organizational",
    "HR": "organizational",
    "PI": "organizational",
    "PS": "organizational",
    "PSS": "organizational",
    "SP": "organizational",
    "SSO": "organizational",
}

_FAM_CONTROL_MAP = {
    "OPS": ControlFamily.INFRASTRUCTURE,
    "CRY": ControlFamily.CRYPTOGRAPHY,
    "IAM": ControlFamily.IAM,
    "OIS": ControlFamily.INFRASTRUCTURE,
    "COS": ControlFamily.INFRASTRUCTURE,
    "DEV": ControlFamily.INFRASTRUCTURE,
    "INQ": ControlFamily.INFRASTRUCTURE,
    "SIM": ControlFamily.INFRASTRUCTURE,
    "AM": ControlFamily.INFRASTRUCTURE,
    "BCM": ControlFamily.INFRASTRUCTURE,
    "COM": ControlFamily.INFRASTRUCTURE,
    "GC": ControlFamily.INFRASTRUCTURE,
    "HR": ControlFamily.INFRASTRUCTURE,
    "PI": ControlFamily.DATA_PROTECTION,
    "PS": ControlFamily.INFRASTRUCTURE,
    "PSS": ControlFamily.INFRASTRUCTURE,
    "SP": ControlFamily.INFRASTRUCTURE,
    "SSO": ControlFamily.INFRASTRUCTURE,
}

_TECHNICAL_RULES = {
    "OPS": {
        "32": {
            "01B": {"requires": ["quote", "measurement"], "desc": "CC policies and procedures"},
            "02B": {"requires": ["quote"], "desc": "Customer information on CC provided"},
            "03B": {"requires": ["quote", "measurement", "build_provenance"], "desc": "CC security requirements"},
        },
        "33": {
            "01B": {"requires": ["quote"], "desc": "Remote attestation offered"},
            "02B": {"requires": ["quote", "measurement"], "desc": "Cryptographic attestation means"},
            "03B": {"requires": ["quote", "measurement", "debug_disabled"], "desc": "Customer verification interface"},
        },
    },
    "CRY": {
        "01": {"01B": {"requires": ["quote"], "desc": "Crypto mechanism policy"}, "02B": {"requires": ["quote", "measurement"], "desc": "Algorithm implementation"}},
        "02": {"01B": {"requires": ["quote"], "desc": "Key management policy"}, "02B": {"requires": ["quote", "measurement"], "desc": "Key generation"}},
    },
    "IAM": {
        "01": {"01B": {"requires": ["quote"], "desc": "Access control policy"}, "02B": {"requires": ["quote", "measurement"], "desc": "Access enforcement"}},
        "02": {"01B": {"requires": ["quote"], "desc": "Identity management"}, "02B": {"requires": ["quote", "measurement"], "desc": "Authentication"}},
    },
    "OIS": {
        "07": {"01B": {"requires": ["quote"], "desc": "Information security risk assessment"}, "02B": {"requires": ["quote", "measurement"], "desc": "Risk treatment"}},
    },
    "COS": {
        "06": {"01B": {"requires": ["quote"], "desc": "Data transmission security"}, "02B": {"requires": ["quote", "measurement"], "desc": "Transmission encryption"}},
    },
    "DEV": {
        "01": {"01B": {"requires": ["build_provenance"], "desc": "Secure development lifecycle"}, "02B": {"requires": ["build_provenance"], "desc": "Development environment"}},
    },
    "INQ": {
        "01": {"01B": {"requires": ["quote"], "desc": "Incident management process"}, "02B": {"requires": ["quote"], "desc": "Incident handling"}},
    },
    "SIM": {
        "01": {"01B": {"requires": ["quote"], "desc": "Security information management"}, "02B": {"requires": ["quote", "measurement"], "desc": "Monitoring"}},
    },
}

_ORG_GAP_REASON = {
    "AM": "Asset inventory requires organizational documentation",
    "BCM": "Business continuity requires documented plans and testing evidence",
    "COM": "Communication procedures require organizational documentation",
    "GC": "General conditions require legal and contractual review",
    "HR": "Human resources require personnel records and training evidence",
    "PI": "Privacy and data protection require legal assessment and DPO documentation",
    "PS": "Physical security requires on-site audit and facility documentation",
    "PSS": "Provisioning and support require service documentation and SLA evidence",
    "SP": "Security policies require documented policy framework review",
    "SSO": "Service level agreements require contractual review and SLA monitoring evidence",
}


def _map_technical_subcriterion(
    family_id: str,
    criterion_id: str,
    sub_id: str,
    graph: EvidenceGraph,
) -> tuple[ComplianceStatus, list[str], str | None]:
    nodes = list(graph.nodes.values())
    quote_nodes = [n for n in nodes if n.node_type == NodeType.QUOTE]
    evidence_ids = [n.node_id for n in quote_nodes]

    family_rules = _TECHNICAL_RULES.get(family_id, {})
    criterion_rules = family_rules.get(criterion_id, {})
    rule = criterion_rules.get(sub_id)

    if rule is None:
        return ComplianceStatus.GAP, [], "No automated evaluation rule defined for this sub-criterion"

    if not quote_nodes and "build_provenance" not in rule.get("requires", []):
        return ComplianceStatus.GAP, [], "No attestation evidence provided"

    required = rule["requires"]
    satisfied_count = 0

    if "quote" in required:
        if quote_nodes:
            satisfied_count += 1

    if "measurement" in required:
        if any(n.measurement is not None for n in quote_nodes):
            satisfied_count += 1

    if "debug_disabled" in required:
        if all(n.debug_disabled is True for n in quote_nodes):
            satisfied_count += 1

    if "build_provenance" in required:
        if any(n.node_type == NodeType.BUILD_PROVENANCE for n in nodes):
            satisfied_count += 1

    ratio = satisfied_count / len(required) if required else 0
    can_verify_workload = any(n.node_type == NodeType.BUILD_PROVENANCE for n in nodes)

    if ratio >= 1.0:
        if "measurement" in required and not can_verify_workload:
            return ComplianceStatus.PARTIAL, evidence_ids, "Measurement exists but cannot be verified against expected reference (requires Measurement CI)"
        return ComplianceStatus.SATISFIED, evidence_ids, None
    if ratio >= 0.5:
        return ComplianceStatus.PARTIAL, evidence_ids, None
    return ComplianceStatus.GAP, evidence_ids, "Insufficient evidence for automated evaluation"


def _map_organizational_subcriterion(
    family_id: str,
    sub: C5Subcriterion,
) -> tuple[ComplianceStatus, list[str], str]:
    reason = _ORG_GAP_REASON.get(family_id, "Requires organizational documentation or human audit")
    return ComplianceStatus.GAP, [], reason


def evaluate_c5_compliance(
    graph: EvidenceGraph,
    c5_dir: str | Path | None = None,
) -> list[ComplianceMapping]:
    """Map evidence graph nodes to C5:2026 control subcriteria. Returns GAP for unmatched controls."""
    if c5_dir is None:
        c5_dir = Path(__file__).parents[2] / "data" / "c5" / "v2026-04-bsi"
    else:
        c5_dir = Path(c5_dir)

    if not c5_dir.is_dir():
        print("warning: C5 control data not found at", c5_dir, file=sys.stderr)
        return []

    families = load_all_c5_families(c5_dir)
    mappings = []

    for family in families:
        family_id = family.family_id
        eval_type = _FAM_EVALUATION_TYPE.get(family_id, "organizational")
        family_ctrl = _FAM_CONTROL_MAP.get(family_id, ControlFamily.INFRASTRUCTURE)

        for criterion in family.criteria:
            criterion_id = criterion.identifier

            for sub in criterion.basic:
                sub_id = sub.identifier
                control_ref = f"{family_id}-{criterion_id}.{sub_id}"

                if eval_type == "technical":
                    status, evidence_ids, gap_desc = _map_technical_subcriterion(
                        family_id, criterion_id, sub_id, graph
                    )
                else:
                    status, evidence_ids, gap_desc = _map_organizational_subcriterion(family_id, sub)

                mappings.append(ComplianceMapping(
                    control_id=control_ref,
                    control_family=family_ctrl,
                    status=status,
                    evidence_node_ids=evidence_ids,
                    gap_description=gap_desc,
                ))

    return mappings


def generate_c5_report(
    graph: EvidenceGraph,
    mappings: list[ComplianceMapping],
    c5_dir: str | Path | None = None,
) -> str:
    """Generate a Markdown C5:2026 compliance report from evaluation results."""
    if c5_dir is None:
        c5_dir = Path(__file__).parents[2] / "data" / "c5" / "v2026-04-bsi"
    else:
        c5_dir = Path(c5_dir)

    if not c5_dir.is_dir():
        return "# C5:2026 Compliance Report\n\nC5 control data not available (download from BSI).\n"

    families = load_all_c5_families(c5_dir)
    lines = [
        "# C5:2026 Compliance Report",
        "",
        "Generated by Confidior Engine",
        "",
    ]

    summary = {
        "SATISFIED": sum(1 for m in mappings if m.status == ComplianceStatus.SATISFIED),
        "PARTIAL": sum(1 for m in mappings if m.status == ComplianceStatus.PARTIAL),
        "GAP": sum(1 for m in mappings if m.status == ComplianceStatus.GAP),
    }

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **SATISFIED:** {summary['SATISFIED']}")
    lines.append(f"- **PARTIAL:** {summary['PARTIAL']}")
    lines.append(f"- **GAP:** {summary['GAP']}")
    lines.append(f"- **Total controls:** {len(mappings)}")
    lines.append("")

    no_rule_count = sum(1 for m in mappings if m.gap_description and "No automated evaluation rule" in m.gap_description)
    if no_rule_count:
        lines.append(f"- **No evaluation rule:** {no_rule_count} (technical controls without automated checks)")
        lines.append("")

    lines.append("## Family Overview")
    lines.append("")
    lines.append("| Family | Type | SATISFIED | PARTIAL | GAP |")
    lines.append("|--------|------|-----------|---------|-----|")

    for family in families:
        family_id = family.family_id
        eval_type = _FAM_EVALUATION_TYPE.get(family_id, "organizational")
        family_mappings = [m for m in mappings if m.control_id.startswith(f"{family_id}-")]
        if not family_mappings:
            continue
        sat = sum(1 for m in family_mappings if m.status == ComplianceStatus.SATISFIED)
        par = sum(1 for m in family_mappings if m.status == ComplianceStatus.PARTIAL)
        gap = sum(1 for m in family_mappings if m.status == ComplianceStatus.GAP)
        lines.append(f"| {family_id} | {eval_type.capitalize()} | {sat} | {par} | {gap} |")

    lines.append("")
    lines.append("## Detailed Results")
    lines.append("")
    lines.append("Only SATISFIED and PARTIAL controls are shown in detail.")
    lines.append("GAP controls are summarized by family above.")
    lines.append("")

    for family in families:
        family_id = family.family_id
        eval_type = _FAM_EVALUATION_TYPE.get(family_id, "organizational")

        family_mappings = [m for m in mappings if m.control_id.startswith(f"{family_id}-")]
        if not family_mappings:
            continue

        non_gap = [m for m in family_mappings if m.status != ComplianceStatus.GAP]
        if not non_gap:
            continue

        lines.append(f"## {family_id} ({eval_type.capitalize()})")
        lines.append("")

        for criterion in family.criteria:
            criterion_id = criterion.identifier
            criterion_non_gap = [
                m for m in non_gap
                if m.control_id.startswith(f"{family_id}-{criterion_id}")
            ]
            if not criterion_non_gap:
                continue

            lines.append(f"### {family_id}-{criterion_id}: {criterion.name}")
            lines.append("")

            for sub in criterion.basic:
                sub_id = sub.identifier
                control_ref = f"{family_id}-{criterion_id}.{sub_id}"
                matching = [m for m in criterion_non_gap if m.control_id == control_ref]
                if matching:
                    status = matching[0].status.value
                    gap_desc = matching[0].gap_description
                    lines.append(f"**{control_ref}** -- {status}")
                    if gap_desc:
                        lines.append(f"  - Note: {gap_desc}")
                    lines.append("")

    lines.append("## GAP Controls Summary")
    lines.append("")
    lines.append("GAP controls fall into two categories:")
    lines.append("")
    lines.append("1. **Organizational controls** (AM, BCM, COM, GC, HR, PI, PS, PSS, SP, SSO) -- require documentation or human audit")
    lines.append("2. **Technical controls without evaluation rules** -- attestation evidence exists but no automated check is defined")
    lines.append("")

    return "\n".join(lines)
