# Confidior Engine Architecture

## Overview

Confidior evaluates evidence and outputs risk-graded assurance assessments with compliance mappings. Right now the evidence types are TEE attestation reports and IaC provenance snapshots, but the architecture is built for more: SBOMs, formal proofs, whatever you can parse into an EvidenceNode. Each evidence type gets its own adapter. The core engine (evidence graph, risk taxonomy, policy evaluator, attack DB) doesn't change.

Input: raw evidence bytes (e.g. attestation report hex). Output: signed EvidenceBundle with assurance level, residual risk, attack analysis, compliance mapping, and optional transparency-log anchor.

## Design Philosophy

**The evidence graph is the technology. TEE attestation is just the first input.**

Most assurance tools are point solutions: one tool for TEE quotes, another for SBOMs, another for compliance checklists. Confidior normalizes all evidence into a graph of nodes and edges, then evaluates the graph against policies and compliance frameworks. Add a new evidence type? Write an adapter. Add a new compliance framework? Write a YAML mapping. The engine stays the same.

**Honest grading, not pass/fail.**

A valid TEE quote doesn't mean you're safe. It means the hardware attested the software. Physical DRAM attacks bypass the hardware. Confidior tracks 44 published attacks (JSON source of truth under `data/attacks/`) with cost estimates, per-platform TCB fix versions, and mitigation status, and factors them into the risk score. When it says CRITICAL, that's not a false positive. It's the answer nobody else will give you.

**Integrates with existing tools, doesn't replace them.**

Confidior doesn't compete with CoCo/Trustee, OPA/Rego, or OneTrust. It eats evidence from attestation libraries, evaluates it, and outputs bundles that other tools can consume. The engine is a layer, not a platform.

## Module Map

```
src/cli/main.py          argument parsing, pipeline orchestration
src/core/                evidence graph, risk engine, policy evaluator, attack DB
src/ingest/              platform adapters (TDX, SEV-SNP, Nitro, IaC) + raw data loaders
src/export/              output: signed bundle, badge SVG, C5 report, Rekor anchoring
src/tools/               archaeology DB, CVE-to-TCB mapper, OpenCVE sync
src/verify/              evidence verification (IaC provenance)
src/web/                 FastAPI web GUI (dashboard, evaluate, results, archaeology, verify-badge)
tests/                   226 passing tests, real + synthetic fixtures
data/attacks/            attack DB JSON source of truth (44 attacks, schema-validated)
```

## Core Pipeline

1. **Ingest**: raw evidence becomes a normalized `EvidenceNode` via a platform-specific adapter (TDX, SEV-SNP, Nitro, IaC).
2. **Risk**: compute `AssuranceLevel` (0-5) and `ResidualRisk` from node properties: TCB status, debug mode, measurement, platform maturity, plus per-attack SVN filtering against the archaeology DB.
3. **Policy**: evaluate the evidence graph against YAML policy rules.
4. **Export**: sign into a DSSE envelope, generate SVG badge with data-commitment, compile C5:2026 compliance report, optionally anchor to Sigstore Rekor via hashedrekord (content never revealed to Rekor).

## Evidence Graph

The evidence graph is the core data structure. Nodes are individual evidence artifacts (quotes, measurements, attestations, policies). Edges are relationships (derives-from, satisfies, references). The graph lets you correlate across platforms, track dependencies, and do multi-hop trust analysis. See `src/core/taxonomy.py` for the full schema.

## Platform Adapters

Each adapter implements two functions:

- `parse_*()`: raw evidence to `EvidenceNode`
- `verify_*()`: optional cryptographic verification

| Adapter | Input Format | Crypto Verification |
|---------|-------------|---------------------|
| TDX     | TDX Quote (tdx-pytools) | Not integrated |
| SEV-SNP | Attestation Report (sev-pytools) | VCEK/VLEK chain |
| Nitro   | COSE_Sign1 CBOR (cbor2) | Certificate chain + signature |
| NVIDIA  | JSON/JWT (secretvm-verify) | NRAS or JWKS |
| IaC     | IaC snapshot (JSON) | Digest verification + provenance attestation |

Verification is non-blocking (`--verify` flag). Failure prints diagnostics but does not halt the pipeline.

## Attack Database

44 published TEE attacks live as schema-validated JSON in `data/attacks/` (aggregate `data/attacks.json`, schema `data/schemas/attack.json`). `scripts/build_attack_db.py` validates and rebuilds it. Two tools consume it:

- `cve_tcb_mapper` maps CVE IDs to per-platform TCB fix versions (CLI: `attacks map-cve-tcb`)
- `cve_sync` fetches high/critical CVEs from OpenCVE and triggers re-scoring of affected bundles (CLI: `attacks sync`)

## Export Formats

- **SVG Badge**: colored shield with level, risk, attestation dimensions, and a data-commitment hash linking badge to bundle
- **C5:2026 Report**: markdown file mapping 462 controls across 18 families to SATISFIED/PARTIAL/GAP
- **Signed Bundle**: Ed25519-signed DSSE envelope containing the full evaluation (graph, policy, risk, compliance)
- **Rekor Entry**: hashedrekord submission to Sigstore public transparency log. Only `sha256(payload)` is stored. The bundle content never leaves your machine.
