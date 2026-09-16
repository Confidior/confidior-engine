"""Display model: the single source every surface reads.

The badge, the report, and the explain lines all derive from the values here,
so they cannot disagree with each other. The allocation is deliberate
(docs/DISPLAY.md):

- **Badge, five items:** the grade and total, the residual-risk tier, the
  platform/quote split, the weakest evidence class, and the attacks that
  counted. Each one changes what a reader does next, each one can be shown
  arithmetically in the explain lines, and each one holds up standing alone
  when the badge is screenshotted out of context.
- **Report, everything:** the same items plus the subscores with their weights
  and meanings, the compliance coverage counts, and every scoring attack with
  the position it demands and the points it cost.
- **Explain, the arithmetic:** one line per deduction, so a reader can argue
  with the number instead of trusting it.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core.taxonomy import AssuranceEvaluation

# Tone vocabulary shared by every surface. "good" and "bad" are reserved for
# claims the engine can defend; "warn" marks a real but non-terminal weakness.
GOOD = "good"
WARN = "warn"
BAD = "bad"
NEUTRAL = "neutral"

_SUBSCORE_MEANINGS = {
    "attestation": "what the evidence proves about this specific quote or report",
    "trust": "confidence in the chain that produced the evidence",
    "threat": "how much known attack surface remains for this platform",
    "freshness": "whether the evidence is recent enough to speak about now",
    "compliance": "share of the criteria this evidence class can speak to",
}

# Display order: the same sequence in the badge and the report, so a reader
# moving between them is not re-orienting.
SUBSCORE_ORDER = ("attestation", "trust", "threat", "freshness", "compliance")


@dataclass(frozen=True)
class Item:
    """One displayable fact: a key for machines, a label for people, a tone."""

    key: str
    label: str
    value: str
    tone: str = NEUTRAL


def _grade_tone(grade: str) -> str:
    if grade in ("F", "D"):
        return BAD
    if grade in ("C", "B"):
        return WARN
    return GOOD


def _risk_tone(risk: str) -> str:
    if risk in ("CRITICAL", "HIGH"):
        return BAD
    if risk == "MEDIUM":
        return WARN
    return GOOD


def _coverage_tone(ratio: float) -> str:
    if ratio >= 0.5:
        return GOOD
    if ratio >= 0.2:
        return WARN
    return BAD


def _scoring_attack_summary(assurance: AssuranceEvaluation) -> tuple[str, str]:
    """The attacks that counted, as a single readable phrase and a tone.

    Positions are included because they are the reason the attack counted: a
    reader needs to know the model granted the host position, not merely that
    something was unmitigated.
    """
    score = assurance.score
    if score is None or not score.scoring_attacks:
        return "none applied", GOOD
    names = [f"{a.name} ({a.position})" for a in score.scoring_attacks]
    unmitigated = any(a.coverage >= 1.0 for a in score.scoring_attacks)
    return f"{len(names)}: " + ", ".join(names), (BAD if unmitigated else WARN)


def badge_items(assurance: AssuranceEvaluation) -> tuple[Item, ...]:
    """The five badge items, in display order."""
    score = assurance.score
    items: list[Item] = []

    if score is None:
        return (Item("grade", "Grade", "ungraded", NEUTRAL),)

    items.append(
        Item("grade", "Grade", f"{score.grade} {score.total}/100", _grade_tone(score.grade))
    )
    risk = assurance.residual_risk.value if assurance.residual_risk else "unknown"
    items.append(Item("risk", "Risk", risk, _risk_tone(risk)))

    if score.platform_score is not None and score.quote_score is not None:
        items.append(
            Item(
                "split",
                "Platform / quote",
                f"{score.platform_score} / {score.quote_score}",
                NEUTRAL,
            )
        )

    if score.evidence_class is not None:
        evidence = score.evidence_class.value
        tone = GOOD if score.evidence_class.strength >= 5 else WARN
        items.append(Item("evidence", "Evidence", evidence, tone))

    value, tone = _scoring_attack_summary(assurance)
    items.append(Item("attacks", "Unmitigated", value, tone))

    return tuple(items)


def subscore_rows(assurance: AssuranceEvaluation) -> tuple[Item, ...]:
    """The five subscores with their weighted value and plain-language meaning.

    Raw values are kept alongside the weighted ones because the weights are a
    profile choice: a reader changing profile needs to see what they changed.
    """
    score = assurance.score
    if score is None:
        return ()
    rows: list[Item] = []
    for key in SUBSCORE_ORDER:
        weighted = score.subscores.get(key)
        if weighted is None:
            continue
        rows.append(
            Item(
                key,
                key,
                f"{weighted}/20 weighted - {_SUBSCORE_MEANINGS.get(key, '')}",
                _grade_tone(score.grade) if weighted < 10 else GOOD,
            )
        )
    return tuple(rows)


def coverage_items(assurance: AssuranceEvaluation) -> tuple[Item, ...]:
    """Compliance coverage: the counts behind the compliance subscore.

    The denominator is stated because it is the honest part of the number: the
    criteria attestation evidence can speak to, with organizational criteria
    counted separately rather than scored as gaps.
    """
    score = assurance.score
    if score is None or not score.compliance_coverage:
        return ()
    c = score.compliance_coverage
    assessable = c.get("assessable", 0)
    ratio = float(c.get("ratio", 0.0))
    return (
        Item(
            "compliance_coverage",
            "Compliance coverage",
            f"{c.get('satisfied', 0)} satisfied, {c.get('partial', 0)} partial, "
            f"{c.get('gap', 0)} gap of {assessable} assessable criteria "
            f"({ratio:.1%}); {c.get('organizational', 0)} organizational, not scored",
            _coverage_tone(ratio),
        ),
    )


def badge_dims(assurance: AssuranceEvaluation) -> dict[str, str]:
    """The badge items as dim-row key/values, for surfaces that render rows.

    Keys match the badge's row vocabulary so the same call feeds the CLI badge
    and the site badge without either re-deriving a value.
    """
    dims: dict[str, str] = {}
    score = assurance.score
    if score is None:
        return dims
    if score.platform_score is not None and score.quote_score is not None:
        dims["split"] = f"platform {score.platform_score} / quote {score.quote_score}"
    if score.evidence_class is not None:
        dims["evidence"] = score.evidence_class.value
    dims["attacks"] = _scoring_attack_summary(assurance)[0]
    return dims


def report_items(assurance: AssuranceEvaluation) -> tuple[Item, ...]:
    """Everything the report adds beyond the badge items."""
    return subscore_rows(assurance) + coverage_items(assurance)


def explain_lines(assurance: AssuranceEvaluation) -> tuple[str, ...]:
    """One line per deduction, in plain arithmetic, so the grade can be argued.

    This is the falsifiability surface: every number the badge shows traces to
    a sentence here.
    """
    score = assurance.score
    if score is None:
        return ("No score: the evidence did not support grading.",)

    lines: list[str] = []
    lines.append(f"Total {score.total}/100 ({score.grade}) under the {score.profile} profile.")
    if score.platform_score is not None and score.quote_score is not None:
        lines.append(
            f"Platform half {score.platform_score}/100 covers the platform's inherent attack "
            f"surface (threat and compliance); quote half {score.quote_score}/100 covers this "
            "evidence's own state (attestation, trust, freshness)."
        )
    for key in SUBSCORE_ORDER:
        weighted = score.subscores.get(key)
        if weighted is None:
            continue
        lines.append(f"{key}: {weighted}/20 weighted - {_SUBSCORE_MEANINGS.get(key, '')}.")

    if score.evidence_class is not None:
        lines.append(
            f"Weakest evidence class: {score.evidence_class.value}. A verdict is only as strong "
            "as its weakest input, so this class caps what the numbers above can mean."
        )

    if score.platform_count >= 2 and score.platforms_bound:
        lines.append(
            f"Platform diversity: {score.platform_count} platforms bound to the same session "
            "(+5 trust). A verdict resting on two independent hardware roots is harder to fake "
            "than one, provided the two attestations cover something in common."
        )
    elif score.platform_count >= 2:
        lines.append(
            f"Platform diversity: {score.platform_count} platforms present with no verified "
            "binding between them, so no trust credit. Two attestations that cover nothing in "
            "common say nothing about each other."
        )

    if score.scoring_attacks:
        lines.append("Threat deductions:")
        for attack in score.scoring_attacks:
            cves = f" ({', '.join(attack.cve_ids)})" if attack.cve_ids else ""
            share = (
                "fully applicable"
                if attack.coverage >= 1.0
                else f"{attack.coverage:.0%} of its vectors still applicable"
            )
            lines.append(
                f"  - {attack.name}{cves} requires the {attack.position} position, "
                f"{share}: -{attack.penalty} from the threat subscore."
            )
    else:
        lines.append("No known attack applied under this threat model.")

    coverage = score.compliance_coverage
    if coverage:
        lines.append(
            f"Compliance coverage: ({coverage.get('satisfied', 0)} + 0.5 x "
            f"{coverage.get('partial', 0)}) / {coverage.get('assessable', 0)} assessable criteria "
            f"= {float(coverage.get('ratio', 0.0)):.1%} of the compliance subscore's 20 points."
        )

    if assurance.boundary_statement:
        first_line = assurance.boundary_statement.splitlines()[0]
    else:
        first_line = "none stated"
    lines.append(f"Boundary: {first_line}")
    return tuple(lines)
