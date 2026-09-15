# Threat Models — the codified constraint sets

*Status: design + spec (2026-09-15). Codifies what the engine's four threat
models mean, why the two software-only models differ, and what each one
excludes. Written because the implementation collapsed them: with no
adversary-position dimension in the attack taxonomy, `software-operator` and
`cloud-admin` produced identical scores despite different trust assumptions.*

## The problem this fixes

An attack record currently declares a **mechanism** category (cache side
channel, interrupt injection, memory-bus interposition, rowhammer, …). Threat
models are defined as sets of those categories. That conflates two different
questions:

1. **How does the attack work?** (mechanism — the `category` field)
2. **Where must the attacker stand?** (position — this spec's new dimension)

Because the taxonomy answers only (1), physical vs software is the only
distinction the models can express, so four labels collapse into two sets.
The consequence: `software-operator` — where the host and hypervisor are
*trusted* — still counts hypervisor-required attacks like Heckler, silently
grading it as worse than its own stated threat model allows.

## The dimension: adversary position

Every attack declares the position(s) from which it can be mounted. The
positions are ordered by increasing capability:

| Position | The attacker stands here | Trusted under this model |
|---|---|---|
| `in-guest` | Inside the workload/CVM — the guest OS, a co-resident process, the application. | The host, hypervisor, and platform |
| `host` | The host: hypervisor, management plane, host OS, CSP admin. | The platform silicon and its firmware |
| `physical` | Physical access to the machine: memory interposition, bus probing, rowhammer equipment. | Nothing below the silicon boundary |
| `supply-chain` | The vendor pipeline: fabrication, firmware supply chain, signing infrastructure, multi-key collusion. | Nothing |

An attack requiring position P is *not* available to an attacker at a lower
position. Model inclusion is therefore derived: a model grants a set of
positions, and only attacks whose required position is in that set count.

## The four models

| Model | Positions granted | Excludes | Buyer context |
|---|---|---|---|
| `software-operator` | `in-guest` | All host-required and physical attacks (the host is trusted) | A workload owner who trusts their platform provider and fears their own code, co-tenants, or stolen credentials |
| `cloud-admin` | `in-guest` + `host` | Physical and supply-chain attacks | The canonical confidential-computing threat model: the cloud provider is the adversary; the TEE exists to defend against it |
| `physical-host` | `in-guest` + `host` + `physical` | Supply-chain | Physical custody is not assured: colocated hardware, seized equipment, untrusted datacenter staff |
| `nation-state-physical` | all four | — | A capable state adversary: fabrication-level attacks, supply-chain compromise, multi-key collusion, undisclosed vulnerabilities |

**This is what makes `software-operator` and `cloud-admin` genuinely
different**, per the 2026-08-19 design note ("they differ in TCB/trust
assumptions, not in physical access"): the trust assumption is *where the
attacker stands*, and it changes which attacks count. Under
`software-operator`, every hypervisor-required attack (Heckler, WeSee,
CIPHERLEAKs, Heracles, page-move attacks, attestation replay) drops out —
not because it stopped existing, but because the model declares that party
trusted.

## Scoring effect

The threat subscore penalizes only attacks whose required position is granted
by the active model. The same evidence therefore grades differently across
models, and the difference is *explainable in one sentence* per attack: "this
attack requires the host position; this model trusts the host."

The `platform` side of the score (T1.2) carries the model-relative attack
surface; the `quote` side is model-invariant. That separation is what makes
the model an input rather than a constant.

## Custom scopes (the constraint sets, per buyer)

Three levels, in the order they ship:

1. **Position include/exclude** — a buyer declares which positions their
   threat model grants. This is the honest minimum: it needs no per-attack
   judgment from the buyer, only a statement about who they fear.
2. **Mechanism include/exclude** — an explicit `AttackCategory` set, for
   buyers who want to reason about mechanisms directly (overrides the
   preset).
3. **Weights** — per-dimension weighting (reuses the score profile), so a
   regulated buyer can weight freshness or compliance above threat.

Sketch (design only):

```yaml
name: bank-physical-insider
positions: [in-guest, host, physical]   # derived set, or presets
categories:                             # optional mechanism override
  include: [speculative_execution, cache_side_channel]
excludes: []
weights:
  threat: 30
  freshness: 25
```

## Unknown-unknowns (unchanged, restated here for completeness)

1. **Coverage signal** — every verdict states the number of known attacks it
   graded against, per platform. A platform with few known attacks is
   *less measured*, never implicitly safer.
2. **Prose disclosure** — the boundary statement carries "undisclosed
   vulnerabilities cannot be detected from a quote" (already live).
3. **Uncertainty discount** — a small discount when coverage is thin and the
   score is high, exposed transparently so a reviewer sees the amount. Gated
   behind the coverage signal so genuinely secure platforms are not
   penalized twice.

## What remains open

- **Position classification for all 43 attacks** — each record needs its
  `adversary_position` set, grounded in its paper. Ambiguous cases (attacks
  requiring an in-guest trigger plus a physical mechanism, e.g. SGX-Bomb)
  need an explicit rule: *position = the strongest capability required*, or
  the attack appears in both sets with a note.
- **Supply-chain position has no attacks yet** — the nation-state model
  currently differs from `physical-host` only nominally. Honest state: the
  dimension exists, the population is empty, and the gap is disclosed rather
  than papered over.
- **Verification-tier interaction** — a `tcb-svn`-verifiable fix removes an
  attack from the count; position is orthogonal to that.
