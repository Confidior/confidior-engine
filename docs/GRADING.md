# Grading — the model, stated in full

*Status: 2026-09-15. Every constant the engine uses to turn evidence into a
grade, so the model can be audited rather than merely re-run. Companion to
`THREAT-MODELS.md` (which model counts which attacks) and to the boundary
statement (what a specific verdict does and does not cover).*

## The pipeline

```
evidence  →  evidence graph  →  unmitigated attacks (per platform, per threat model)
          →  five subscores on a 0–20 raw scale
          →  weighted to 0–100 (score profile)
          →  total, grade letter, residual-risk tier
          →  policy evaluation (a separate layer: turns the grade into ALLOW/WARN/DENY)
```

The score and the decision are deliberately separate. The score is a
measurement; the decision is a policy choice about that measurement.

## The five subscores (raw scale 0–20)

| Dimension | Formula | Source of truth |
|---|---|---|
| **attestation** | `min(assurance_level × 4, 20)` | The assurance level (0–5) derived from the evidence graph |
| **trust** | sum of five conditions, +5 each, capped at 20 | Evidence graph structure |
| **threat** | `max(20 − Σ(cost_penalty + difficulty_penalty), 0)` | The curated attack DB, filtered by platform and threat model |
| **freshness** | FRESH → 20, AGING → 12, STALE → 0 | Node timestamps against TTLs |
| **compliance** | `round(coverage_ratio × 20)` over the evidence-assessable criteria; organizational criteria excluded from the denominator | C5 evaluation statuses (satisfied / partial / gap); attack→control ratio as fallback when control data is absent |

### attestation

The assurance level ladder: 0 NONE, 1 CONFIG_VERIFIED, 2 HARDWARE_ATTESTED,
3 OPERATIONAL_ASSURANCE, 4 DISTRIBUTED_TRUST, 5 CRYPTOGRAPHIC_PRIVACY. The
×4 scaling means a genuine hardware attestation starts at 8/20 and only
levels 3–5 approach the ceiling. **Open calibration:** whether a correct
Level-2 quote should cap at 8 is flagged below.

### trust — the five conditions

Each adds 5, capped at 20:

1. Debug mode disabled on every quote node
2. TCB resolved as current (against a reference or the live vendor lookup)
3. A build-provenance node is present
4. Provenance dimension resolves to `chained`
5. Two or more platforms in the graph (corroboration)

### threat — the penalty tables

Per applicable unmitigated attack, subtracted from 20:

| Cost to attack | Penalty | | Mitigation difficulty | Penalty |
|---|---|---|---|---|
| `~$10` | 10 | | `no_mitigation_available` | 10 |
| `~$50` | 8 | | `hardware_redesign_required` | 6 |
| `~$1,000` | 4 | | `firmware_patch_available` | 2 |
| `unknown` | 5 | | `microcode_update_available` | 2 |
| | | | `software_fix_available` | 1 |

Cost dominates difficulty on purpose: a cheap attack is worse than an
expensive one regardless of how hard the fix is.

"Unmitigated" is strict. An attack counts against the score unless a
mitigation is **verified**: an attack is excluded only when its `patched`
flag is set, when the quote's TCB meets the attack's curated `min_svn`
threshold, or when the attack's `mitigation_verification` tier is satisfied
by evidence the engine holds. An unverifiable mitigation (kernel-side fixes
awaiting the anchoring layer) counts as unmitigated — see
`THREAT-MODELS.md` and the attack records' `mitigation_verification` field.

### freshness

Computed from node timestamps against a default TTL: all nodes within TTL →
FRESH; any node past 80% of TTL → AGING; any node past TTL → STALE. Nodes
without timestamps are skipped rather than assumed fresh.

## Weights and grade thresholds (the profiles)

`weighted[dim] = round(raw / 20 × weight)`, then the dimensions sum to the
total (clamped 0–100).

| Profile | attestation | trust | threat | freshness | compliance | A | B | C | D |
|---|---|---|---|---|---|---|---|---|---|
| **default** | 20 | 20 | 20 | 20 | 20 | 90 | 75 | 60 | 45 |
| **finance** | 15 | 25 | 15 | 25 | 20 | 92 | 80 | 65 | 50 |
| **gpu-tee** | 15 | 25 | 25 | 20 | 15 | 88 | 75 | 60 | 45 |

The thresholds are the floors for each letter; below D is F. `finance`
weights freshness and compliance higher (a stale verdict is a liability in a
regulated context); `gpu-tee` weights threat higher (accelerator attack
surface moves fastest). A profile changes emphasis, never the measurement —
the subscores are identical across profiles.

## Residual risk

Derived from the applicable attack set, not from the score:

- No applicable attacks → the base tier stands
- Any **cheap** attack (`~$10`, `~$50`) or any attack with **no mitigation**
  available → CRITICAL, regardless of base
- Otherwise, any attack needing a **hardware redesign** escalates one tier
  (LOW→MEDIUM→HIGH→CRITICAL)
- Otherwise, any other applicable attack escalates one tier

Risk and score can disagree by design: a high score with one cheap
unmitigated attack is HIGH or CRITICAL risk, because risk answers "what is
the worst reachable outcome" while the score answers "how much evidence
supports the claim."

## The platform/quote split

Two numbers derived from the same subscores:

- **platform** = `(threat + compliance) / 40 × 100` — the attack surface of
  the platform class, under the active threat model
- **quote** = `(attestation + trust + freshness) / 60 × 100` — this specific
  attestation's state

The quote side is threat-model-invariant; the platform side moves with it.
Worked example (RedPill TDX node, verified 2026-09-15 by running the engine):

| Model | total | threat | platform | quote |
|---|---|---|---|---|
| software-operator | 54 | 20 | 52 | 55 |
| cloud-admin | 51 | 17 | 45 | 55 |
| physical-host | 41 | 7 | 20 | 55 |
| nation-state-physical | 41 | 7 | 20 | 55 |

The last two are numerically identical because no attack in the curated database
currently discriminates them: both models grant the physical position, and the
database records no attack that distinguishes a state actor from any other
physical adversary. The difference between the two models is currently in their
stated assumptions rather than in the score.

## The coverage signal

Every verdict states how many known attacks it graded against, per platform,
and the boundary statement carries: "undisclosed vulnerabilities cannot be
detected from a quote." A platform with few known attacks is **less
measured**, never implicitly safer.

## Open calibration (decisions not yet taken)

1. **The attestation ceiling.** A correct Level-2 quote scores 8/20 on
   attestation. Should evidence quality beyond the level raise it, or is the
   level the honest cap?
2. **The evidence-class dimension.** Provenance should distinguish computed
   golden values, captured values, vendor-published values, point-in-time
   reports, and runtime-anchored evidence. Tracked as task #6.

**Compliance resolved 2026-09-15.** The dimension is now framework-relative
coverage: `(satisfied + 0.5 × partial) / assessable` over the technical
families, with organizational families counted separately and never scored as
gaps. Worked example (RedPill TDX): 11 satisfied, 9 partial, 266 gap,
286 assessable, 176 organizational → 5.4% → 1/20. Previously the same
evidence scored 0 because every control mapped by one unpatched attack was
treated as a gap across all frameworks at once.

**Attack weights resolved 2026-09-15.** `mitigation_coverage` (default 1.0)
scales each attack's penalty by the share of its vectors still applicable, so
a partially mitigated attack counts as less than a whole one. Heckler carries
0.5: int 0x80 is patched, other effect-handler interrupts are not, and TDX
blocks low-vector interrupts in hardware.

## What this spec does not decide

- **Whether to allow.** The policy layer reads the grade and the risk tier;
  the thresholds there are the buyer's, not the model's.
- **How a verdict is displayed.** The display design is task #7.
- **What a verdict covers.** That is the per-verdict boundary statement, which
  is generated from the evidence state (see the working notes).
