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

## What the engine does instead

The `compliance` dimension of the score is **policy conformance**, not
framework coverage: the severity-weighted share of the policy this evidence
satisfies. When no policy is evaluated the dimension is absent and the
remaining dimensions are renormalized, so a grade never moves because a policy
was or was not supplied without saying so. See `GRADING.md`.

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
