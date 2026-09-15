# Display: what surfaces where

This document decides how a verdict reaches a reader. The grading model states
what the numbers mean (`GRADING.md`); this states which of them a reader sees,
where, and why.

The model produces more than any single surface should carry. Three surfaces,
each with one job:

| Surface | Audience | Job |
|---|---|---|
| Badge | scanning, often out of context | carry the claim and its limits |
| Report | evaluating, comparing vendors | carry the detail and the denominators |
| Explain | arguing, auditing | carry the arithmetic, line by line |

All three read one derivation (`src/export/display.py`). No surface re-computes
a value, so they cannot disagree about a number. The badge on confidior.com and
the badge written by the CLI are the same five items from the same function.

## The badge: five items

| Item | Example | What the reader does next |
|---|---|---|
| Grade and total | `D 51/100` | forms the headline judgement |
| Residual risk | `HIGH` | decides whether to escalate |
| Platform / quote split | `platform 45 / quote 55` | learns which half of the claim is weak, and what to ask the vendor for |
| Evidence class | `point-in-time` | decides how much the number is worth at all |
| Attacks that counted | `1: Heckler (host)` | knows what remains unmitigated, and why it applied |

Grade and risk are deliberately separate. **Grade is how much we know. Risk is
how bad it would be if we are wrong.** A vendor can score well on a weak threat
model and carry high residual risk at the same time; collapsing the two would
hide exactly the case a buyer needs to see.

The split is the differentiator: no other verifier tells you whether the weak
part of a claim is the platform or this particular quote.

The attack list carries the position because that is the reason the attack
counted. `Heckler (host)` says the threat model granted the host position; a
reader who disagrees with that assumption has found the argument to have.

## Report membership test

An item belongs on the badge when it passes all three:

1. **Does it change what the reader does next?** If a reader would act the same
   way without it, it belongs in the report.
2. **Can the engine show how it was computed?** Every badge item traces to a
   sentence in the explain lines. Anything that cannot be traced stays off the
   badge until it can be.
3. **Does it hold up standing alone?** Badges are screenshotted, embedded, and
   quoted without their surrounding page. Each item must be true and
   unambiguous on its own, including its own limits.

## The report: everything, with denominators

The report adds the five subscores with their weighted values and plain-language
meanings, the compliance coverage counts, and every scoring attack with its
required position, remaining coverage, and point cost.

The denominator is stated wherever a ratio appears. `11 satisfied, 9 partial,
266 gap of 286 assessable criteria (5.4%); 176 organizational, not scored` is
honest about its scope; `5.4% compliant` is not, because it hides which criteria
the evidence could ever speak to.

## The explain path: the arithmetic

Explain lines state one deduction each, in the order they were applied, so a
reader can argue with the number instead of trusting it. Worked example, the
RedPill TDX quote under the cloud-admin threat model:

```
Total 51/100 (D) under the default profile.
Platform half 45/100 covers the platform's inherent attack surface (threat and
compliance); quote half 55/100 covers this evidence's own state (attestation,
trust, freshness).
attestation: 8/20 weighted - what the evidence proves about this specific quote.
trust: 5/20 weighted - confidence in the chain that produced the evidence.
threat: 17/20 weighted - how much known attack surface remains.
freshness: 20/20 weighted - whether the evidence is recent enough to speak about now.
compliance: 1/20 weighted - share of the criteria this evidence class can speak to.
Weakest evidence class: point-in-time. A verdict is only as strong as its weakest
input, so this class caps what the numbers above can mean.
Threat deductions:
  - Heckler (CVE-2024-25743, CVE-2024-25744) requires the host position, 50% of
    its vectors still applicable: -3 from the threat subscore.
Compliance coverage: (11 + 0.5 x 9) / 286 assessable criteria = 5.4% of the
compliance subscore's 20 points.
```

Every number on the badge for this verdict appears above, in the form someone
would need to challenge it.

## Rules the surfaces obey

- **Never claim stronger provenance than the weakest input.** The badge reports
  the weakest evidence class, and an unstated class reads as the weakest one.
- **"None applied" is a result, not a rendering of zero.** An empty threat set
  under a restrictive threat model reads as good; it is not the same as an
  unmeasured platform.
- **A low attack count is not safety.** The boundary statement states how many
  known attacks the platform was graded against; a low number means less
  measured, and that sentence travels with the verdict.
- **Tone tracks severity, not identity.** Grade, risk, evidence class, and
  coverage each carry their own thresholds; nothing inherits the colour of the
  headline.

## What is deliberately not on the badge

TCB version and status, debug state, measurement match, freshness, and the
boundary statement. Each matters, and each either duplicates a badge item
(measurement match is upstream of the grade) or needs context to be read
correctly (a TCB status means nothing without the reference it was checked
against). They stay in the report, where they sit next to the values that make
them interpretable.

## Open display questions

- **Should the badge show the threat model by name?** It carries the positions
  today; naming the model (`cloud-admin`) would make the assumption explicit
  and the badge wider.
- **Does the split need labels?** `platform 45 / quote 55` assumes the reader
  has met the distinction. A one-line explanation may belong on the badge page
  rather than the image.
- **Evidence class vocabulary.** `point-in-time` and `computed-golden` are
  precise and unfamiliar. The report defines them; the badge does not.
