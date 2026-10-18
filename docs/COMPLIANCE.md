# Compliance mapping

Compliance mapping is **not part of grading**. The engine's output is an
evidence bundle. Mapping that evidence onto a framework's checklist is a
downstream reading of it, and that reading lives in `src/compliance/`, outside
the path `confidior verify` takes.

## Why it is separate

**The checklist is not the product.** Most criteria in a framework like C5:2026
are organizational: whether a policy document exists, whether an auditor
interviewed staff. A TEE quote cannot speak to them. Running the old mapper on
a real TDX quote produced 11 SATISFIED, 9 PARTIAL and 442 GAP out of 462
controls, and 264 of those controls had no evaluation rule at all. The result
says more about the catalogue than about the workload.

**Licensing.** The C5:2026 catalogue is BSI's, published under CC BY-ND 4.0 for
non-commercial use. The engine is Apache 2.0. Shipping a mapping that requires
BSI's terms would put the engine's licence in tension with its data, so the
catalogue is not in the repository and the mapping is opt-in.

**Someone else maintains the frameworks.** Executable control libraries now
cover the frameworks most users ask for. Consuming them beats re-deriving them.

## The policy engine is not OPA

`src/core/policy.py` evaluates Rego with `regopy`, which wraps
[Microsoft's rego-cpp](https://github.com/microsoft/rego-cpp): a C++
implementation, not a binding to the Go `opa` library. That distinction matters
to anyone porting a policy, so it is stated here rather than discovered.

**What it gives us.** In-process evaluation with no `opa` binary or sidecar,
which the verify path needs to stay self-contained, and wheels for CPython
3.10-3.14 on Linux, macOS and Windows. The rule vocabulary our policies use
(sets, comprehensions, `object.get`, `sprintf`, `every`, `walk`, `else`) behaves
as OPA documents it.

**Where it differs, verified against `regopy` 1.5.2:**

- **Imports are not enforced.** `import rego.v1`, `import rego.v2`, and
  `import totally.not.a.thing` all parse without complaint, and 0.x syntax
  (`deny["x"] { ... }`) is accepted even inside a module that declares
  `import rego.v1`. So a policy written to the pre-1.0 spelling will load here
  and fail under real OPA. Treat `import rego.v1` in our fixtures as a
  declaration to the reader, not as a check the engine performs.
- **Recursion is not rejected.** OPA refuses recursive rules at parse time
  precisely because policy evaluation must terminate. rego-cpp accepts direct
  and mutual recursion at parse time and fails during evaluation, handing back
  an empty payload that surfaces as a `JSONDecodeError` from inside `query()`.
  `_query` converts that into a `PolicyError` naming the likely cause, so it is
  a clean error rather than a traceback, but it is a runtime failure where OPA
  would have made it a load-time one. A policy that arrives at runtime from an
  untrusted source should be parsed by real OPA first.
- **`rego.v2` is not a feature.** It parses because *every* import parses. It
  does not select v2 semantics.

None of these affect the default policy or the fixtures, which are verified
independently above. They matter when loading third-party libraries such as
`ynotbhatc/rego_policy_libraries`, which are written for OPA proper.

### On Rego not being Turing-complete

Rego is deliberately **not** Turing-complete: no `while` loops, no recursion
under real OPA, evaluation guaranteed to terminate. That is a feature for a
verifier, not a limitation. The policy runs inside the thing that is supposed to
produce an answer; a policy that can loop forever is a denial-of-service surface
in the verification path. rego-cpp's weaker guarantee here is the one place the
choice costs us, and the `PolicyError` conversion above is the mitigation.

### The "Rego tax" and what it means here

The standing complaint against Rego is not expressiveness but authoring
ergonomics: no schema checked at authoring time, so a payload whose shape drifts
silently changes what a policy means. In ordinary infrastructure policy this
produces confusing failures. In a verifier it produces **wrong answers**, and
we found one in our own default policy:

```rego
# The obvious spelling. Wrong.
q.debug_disabled != true
```

When `debug_disabled` is absent, that body is undefined, so it never fires and
the rule reports **satisfied**. An evidence producer that stopped emitting the
field would have relaxed the policy without failing anything. The same shape of
bug applied to `assurance.level`: an absent level skipped the threshold check
entirely, and an absent `evidence` key made the "no evidence" rule pass
vacuously.

The default policy is now written fail-closed: every field read goes through
`object.get` with a default that fails the rule, an absent field is reported as
its own finding ("missing or not a boolean") rather than folded into the real
failure, and an absent assurance level is a distinct finding instead of being
silently treated as passing. `tests/test_policy.py` pins all three cases.

This is why the split below matters more than the language choice: the engine's
job is to state what the evidence says, and a policy that fails open is worse
than no policy at all.

## What the engine does instead

The `compliance` dimension of the score is **policy conformance**, not
framework coverage: the severity-weighted share of the policy this evidence
satisfies. When no policy is evaluated the dimension is absent and the
remaining dimensions are renormalized, so a grade never moves because a policy
was or was not supplied without saying so. See `GRADING.md`.

## Why Rego, and what the alternatives were

The decision is recorded here because it is the kind of choice a reader will
want to re-litigate once. The short version: Rego was chosen for the
**termination guarantee plus the existing corpus**, not because it is the
fastest or the most ergonomic language available.

| Language | What it would have given us | Why it was not chosen |
|---|---|---|
| **Rego** (chosen) | Terminating by construction; the attestation ecosystem (Trustee, Keylime, Veraison, Intel Trust Authority) and roughly 800 published control policies across ~175 catalogues already express policy in it | Weakest authoring ergonomics of the group; no author-time schema checking. A C++ reimplementation of the engine, with the gaps listed above |
| **Cedar** (AWS) | Strict typed schema catches attribute errors *at authoring time*, faster evaluation, formal verification (SMT/Lean) that privilege escalation is impossible | Narrower ecosystem and AWS-centric. The typed-schema guarantee is genuinely the best answer to the Rego tax, but adopting it would have forfeited the Rego corpus, which was the whole point |
| **CEL** | Runs natively in the Kubernetes API server at microsecond speeds | Stateless and context-free: no partial evaluation, no graph traversal. Our input *is* a graph, so this is the wrong shape |
| **Cerbos** (YAML + CEL) | Fastest to adopt, built-in deny-overrides | No partial evaluation, no property analysis, no graph traversal |
| **OpenFGA / SpiceDB** | Purpose-built relationship-graph traversal | Solves "who is related to what", not "does this evidence satisfy this appraisal policy". No general policy language |
| **SAPL** | Only engine with streaming authorization and first-class obligations (redaction, approvals) | Small, JVM-centric ecosystem; the streaming model solves a problem we do not have, since a verdict is produced once per bundle, not continuously |
| **Mangle** (Google) | Datalog with aggregation, function calls, optional type checking, embeddable as a Go library | Program-analysis focus; no policy distribution/enforcement ecosystem, and it is Go-only, so it would need a sidecar to reach this engine |
| **Cedar + Dogwood** (temporal) | Reasons over sequences and history, which point-in-time checks cannot | Research-stage; the problem it targets (an agent splitting a spend cap across concurrent calls) is not our problem |

Two points worth recording:

- **Rego's immaturity risk is real but bounded.** Rego v2 is in active
  development upstream and Styra DAS, the commercial OPA offering, is moving to
  community-maintained open source. Neither affects this engine, which embeds a
  C++ reimplementation whose feature set is fixed and vendored, not a rolling
  OPA dependency. It does mean the "load upstream OPA libraries unchanged"
  promise should be re-verified when `regopy` is upgraded, not assumed.
- **Nothing here is a verdict on Cedar.** If the requirement ever changes from
  "consume the policy corpus that exists" to "be provably safe about a narrow
  attribute language", Cedar is the better answer. It is not the better answer
  today.

Cedar, CEL and Cerbos are all faster than Rego at pure authorization checks;
benchmarks put Rego 40-80x behind Cedar on microsecond-scale decisions. That
number is irrelevant here: policy evaluation is one step in a verification
pipeline that spends its time on attestation parsing and signature checking, so
the policy cost does not appear in any profile.

## Using this package

```bash
# Fetch the catalogue first (opt-in; CC BY-ND 4.0, non-commercial)
uv run --no-project python scripts/fetch_c5_data.py

# Render the mapping for one attestation
uv run python -m src.cli.main compliance --input quote.hex --platform tdx
```

The report goes to stdout, or to `--output`. Python callers can use
`evaluate_c5_compliance(graph)` and `generate_c5_report(graph, mappings)`
directly.

## Using an upstream Rego library instead

`ynotbhatc/rego_policy_libraries` carries a C5:2026 module covering all 168
criteria with a uniform `compliance_report` entrypoint. Because the policy
layer is Rego (`src/core/policy.py`), those modules load without changes:

```bash
git clone --depth 1 https://github.com/ynotbhatc/rego_policy_libraries
```

One caveat, stated upstream: that module's C5 criteria are **attestation-only**.
Every criterion is decided by `input.bsi_c5.criteria["OPS-01"] == true` rather
than by facts about the system. Adopting it does not add automated checking; it
replaces a hand-rolled mapping table with a maintained one.

The libraries worth knowing about, by what they actually codify:

| Library | Codifies | Fit |
|---|---|---|
| `ynotbhatc/rego_policy_libraries` | System-state across ~175 framework catalogues | Load as Rego; supplies the control layer |
| `pulumi/compliance-policies` | Cloud resource configuration (TypeScript) | Different engine; not loadable here |
| `advanced-security/policy-as-code` | GitHub scanning thresholds (YAML) | Different domain |
| Kubescape `regolibrary` | Kubernetes controls | Load as Rego |

GRC platforms (`theopenlane/core`, `trycompai/comp`, `UnicisTech/unicis-platform-ce`,
`strongdm/comply`) are where a checklist *belongs*: downstream of the engine,
consuming evidence bundles. The engine produces the artifact; those systems
collect and file it.
