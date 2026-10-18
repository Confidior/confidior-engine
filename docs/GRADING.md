# Grading: the model, stated in full

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
| **compliance** | `round(conformance_ratio × 20)`, severity-weighted over the policy's rules (high 3, medium 2, low 1); absent when no policy was evaluated | The Rego policy's own rule outcomes (`src/core/policy.py`) |

### attestation

The assurance level ladder: 0 NONE, 1 CONFIG_VERIFIED, 2 HARDWARE_ATTESTED,
3 OPERATIONAL_ASSURANCE, 4 DISTRIBUTED_TRUST, 5 CRYPTOGRAPHIC_PRIVACY. The
×4 scaling means a genuine hardware attestation starts at 8/20 and only
levels 3–5 approach the ceiling. **Open calibration:** whether a correct
Level-2 quote should cap at 8 is flagged below.

### trust: the five conditions

Each adds 5, capped at 20:

1. Debug mode disabled on every quote node
2. TCB resolved as current (against a reference or the live vendor lookup)
3. A build-provenance node is present
4. Provenance dimension resolves to `chained`
5. Two or more platforms in the graph **bound to a shared session** (corroboration)

Condition 5 requires a verified binding rather than a platform count: a
`BOUND_TO` edge between quote nodes on different platforms whose shared material
(a challenge, session-key hash or workload digest) matches. Two attestations
that cover nothing in common say nothing about each other, so an unbound second
platform is reported in the verdict (`platform_count`, `platforms_bound`) without
trust credit. The same condition gates the distributed-trust assurance level, for
the same reason.

### threat: the penalty tables

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
awaiting the anchoring layer) counts as unmitigated, see
`THREAT-MODELS.md` and the attack records' `mitigation_verification` field.

### freshness

Computed from node timestamps against a default TTL: all nodes within TTL →
FRESH; any node past 80% of TTL → AGING; any node past TTL → STALE. Nodes
without timestamps are skipped rather than assumed fresh.

## Weights and grade thresholds (the profiles)

`weighted[dim] = round(raw / 20 × weight)`, then the dimensions sum to the
total (clamped 0–100).

When a dimension is absent — the case for `compliance` when no policy was
evaluated — its weight is neither credited nor charged. The weighted sum is
rescaled `× 100 / (sum of the weights present)`, so the total stays a 0–100
grade over what was actually measured. Scoring an unmeasured dimension full
marks would raise every grade the moment no policy was supplied; scoring it
zero would punish evidence for a question it was never asked.

| Profile | attestation | trust | threat | freshness | compliance | A | B | C | D |
|---|---|---|---|---|---|---|---|---|---|
| **default** | 20 | 20 | 20 | 20 | 20 | 90 | 75 | 60 | 45 |
| **finance** | 15 | 25 | 15 | 25 | 20 | 92 | 80 | 65 | 50 |
| **gpu-tee** | 15 | 25 | 25 | 20 | 15 | 88 | 75 | 60 | 45 |

The thresholds are the floors for each letter; below D is F. `finance`
weights freshness and compliance higher (a stale verdict is a liability in a
regulated context); `gpu-tee` weights threat higher (accelerator attack
surface moves fastest). A profile changes emphasis, never the measurement -
the subscores are identical across profiles.

## Why the threat dimension saturates

The threat dimension does not subtract the attack penalty linearly from 20.
It is:

```
threat = 20 * H / (H + raw_penalty),  H = 20
```

where `raw_penalty` is the sum of the per-attack penalties for every attack
in scope under the threat model. So no in-scope attacks gives 20, a raw
penalty of 20 gives 10, and the value approaches 0 without reaching it.

This replaced a `max(0, 20 - raw_penalty)` clamp. The clamp was wrong once a
platform carried enough attacks: an Intel TDX quote now accrues a raw penalty
of 31 under `cloud-admin` and 41 under `physical-host`, and both clamped to
the same zero. "The same quote grades differently under each threat model" is
a documented product property, and the clamp silently falsified it. A curve
that is strictly decreasing in the penalty preserves the ordering at every
penalty level while staying bounded by 20, so the weighted sum still holds.

Ordering is the whole point: with the curve, a TDX quote scores 54 under
`software-operator`, 42 under `cloud-admin`, 40 under `physical-host` and 40
under `nation-state-physical`. Under the old clamp, `cloud-admin` and
everything above it all scored the same 34. `physical-host` and
`nation-state-physical` still tie because no attack in the DB requires the
supply-chain-only position yet, which is the open item in `docs/THREAT-MODELS.md`.

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

- **platform** = `threat / 20 × 100`, the attack surface of the platform
  class, under the active threat model
- **quote** = `(attestation + trust + freshness + compliance) / (20 × n) × 100`
  over the dimensions present (n = 4 with a policy, 3 without), this specific
  attestation's state

Policy conformance sits on the quote side: framework coverage was a property of
the platform (the same control data applied to every quote), while whether
*this* evidence satisfies *this* policy is a property of the evidence.

The quote side is threat-model-invariant; the platform side moves with it.
Worked example (RedPill TDX node, verified 2026-09-15 by running the engine):

| Model | total | threat | platform | quote |
|---|---|---|---|---|
| software-operator | 66 | 20 | 100 | 55 |
| cloud-admin | 51 | 8 | 38 | 55 |
| physical-host | 49 | 6 | 32 | 55 |
| nation-state-physical | 49 | 6 | 32 | 55 |

Measured 2026-10-18 with no policy evaluated, so the compliance dimension is
absent and the graded weight is 80 of 100. The same quote under a policy it
partly fails scores lower: with 3 of 9 severity-weighted points satisfied the
total is 48 and the quote half drops to 50.

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
2. **The evidence-class dimension.** Resolved, one axis not two. The ladder is
   `provenance_rank`: how the evidence was obtained (computed golden, captured,
   vendor-published, point-in-time report, runtime-anchored). It is not a
   strength scale. A second axis, `standing`, what process accepts the evidence
   is proposed in `docs/VERIFIABILITY.md` and is not built; until it is, a
   verdict reports provenance only and does not claim that stronger provenance
   is stronger evidence.

**Compliance resolved 2026-10-18.** The dimension measures **policy
conformance**, not framework coverage: `(severity-weighted satisfied) / (total
weight)`, with high 3, medium 2, low 1. Worked example (RedPill TDX under the
default policy): 3 of 9 weighted points → 33% → 7/20. The dimension is absent
when no policy is evaluated, and the total renormalizes over the dimensions
present.

This replaced framework-relative coverage, which measured `(satisfied + 0.5 ×
partial) / assessable` over C5's technical families. On a real TDX quote that
produced 11 satisfied, 9 partial, 266 gap of 286 assessable, and 264 of the 462
controls had no evaluation rule at all: 20% of the grade moved on a hand-written
table that mostly said "not defined". Coverage of a catalogue also says nothing
about the question a reader actually has, which is whether this evidence meets
the policy it is being judged against.

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
