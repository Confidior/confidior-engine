# Dependencies & Upstream Credits

Confidior is built on top of existing open-source libraries and upstream projects. This document lists all external dependencies, their licenses, and how Confidior uses them.

## Core Attestation Libraries

### tdx-pytools

- **Source:** [TEE-Attestation/tdx_pytools](https://github.com/TEE-Attestation/tdx_pytools)
- **License:** MIT
- **Copyright:** 2025 Hewlett Packard Enterprise Development LP
- **Confidior role:** Raw Intel TDX quote parsing. Confidior wraps the parser output into normalized `EvidenceNode` dataclasses. We do not modify, fork, or vendor this library.
- **Install:** git-sourced in `pyproject.toml` (`[tool.uv.sources]`), pinned to the upstream repo.

### sev-pytools

- **Source:** [TEE-Attestation/sev_pytools](https://github.com/TEE-Attestation/sev_pytools)
- **License:** MIT
- **Copyright:** 2025 Hewlett Packard Enterprise Development LP
- **Confidior role:** Raw AMD SEV-SNP report parsing. Confidior wraps the parser output into normalized `EvidenceNode` dataclasses. We do not modify, fork, or vendor this library.
- **Install:** git-sourced in `pyproject.toml` (`[tool.uv.sources]`), pinned to the upstream repo.

## Cryptography

### cryptography (PyCA)

- **Source:** [pyca/cryptography](https://github.com/pyca/cryptography)
- **License:** Apache-2.0 / BSD-3-Clause
- **Confidior role:** Ed25519 key generation and DSSE envelope signing.

## Data Formats

### cbor

- **Source:** [agronholm/cbor2](https://github.com/agronholm/cbor2) (PyPI: `cbor`)
- **License:** MIT
- **Confidior role:** AWS Nitro Enclaves COSE_Sign1 CBOR decoding.

### pyyaml

- **Source:** [yaml/pyyaml](https://github.com/yaml/pyyaml)
- **License:** MIT
- **Confidior role:** C5:2026 control ingestion (opt-in, `src/compliance/` only).

## Policy

### regopy

- **Source:** [microsoft/rego-cpp](https://github.com/microsoft/rego-cpp) (PyPI: `regopy`)
- **License:** MIT
- **Confidior role:** Evaluates Rego policy in-process (`src/core/policy.py`). No
  `opa` binary or sidecar. Wheels ship for CPython 3.10-3.14 on Linux, macOS and
  Windows. Chosen over an external OPA process because the verify path must stay
  self-contained, and over a bespoke expression language because the attestation
  ecosystem (Trustee, Keylime, Veraison, Intel Trust Authority) and the published
  control libraries all express policy in Rego.
- **Not OPA.** This is Microsoft's C++ implementation, not a binding to the Go
  `opa` library. Verified differences at 1.5.2: imports are not enforced
  (`import rego.v1`, `rego.v2` and unknown imports all parse; 0.x syntax is
  accepted inside a `rego.v1` module), and recursion is accepted at parse time
  and fails at evaluation instead of being rejected. The second is converted to
  a `PolicyError` in `_query`. See `COMPLIANCE.md`; re-verify on upgrade.
- **Measured coverage:** 368 of 371 policy modules (99.2%) from
  `ynotbhatc/rego_policy_libraries` load, including the C5:2026 package. The
  misses are `every` in a rule head and `some` inside a comprehension. OPA via
  WASM (`wasmtime`) is the documented alternative if exact OPA semantics become
  a requirement; it was rejected for now because it reintroduces the `opa`
  build step.

## Build tooling (script deps, not runtime)

### jsonschema

- **Source:** [python-jsonschema/jsonschema](https://github.com/python-jsonschema/jsonschema)
- **License:** MIT
- **Confidior role:** Validates `data/attacks/*.json` against `data/schemas/attack.json` via
  `scripts/build_attack_db.py validate`. Used ephemerally (`uv run --with jsonschema`), not a
  project dependency.

## Web Layer

### fastapi, uvicorn, jinja2, python-multipart

- **Source:** [fastapi/fastapi](https://github.com/fastapi/fastapi), [encode/uvicorn](https://github.com/encode/uvicorn), [pallets/jinja](https://github.com/pallets/jinja), [andrew-d/python-multipart](https://github.com/andrew-d/python-multipart)
- **License:** MIT / BSD-3-Clause (fastapi), BSD-3-Clause (uvicorn), BSD-3-Clause (jinja2), Apache-2.0 (python-multipart)
- **Confidior role:** FastAPI web GUI, dashboard, evaluate, results, archaeology, verify-badge routes. Templates are Jinja2 server-rendered.

## Networking

### requests

- **Source:** [psf/requests](https://github.com/psf/requests)
- **License:** Apache-2.0
- **Confidior role:** OpenCVE API client for live CVE sync (`src/tools/cve_sync.py`, CLI `attacks sync`).

### python-dotenv

- **Source:** [theskumar/python-dotenv](https://github.com/theskumar/python-dotenv)
- **License:** BSD-3-Clause
- **Confidior role:** Reads `OPENCVE_API_TOKEN` / `OPENCVE_*` credentials for the sync tool from `.env`.

### cvm-attest

- **Source:** [TEE-Attestation/cvm_attest](https://github.com/TEE-Attestation/cvm_attest)
- **License:** MIT
- **Confidior role:** Intel TDX quote verification (`src/ingest/adapters/tdx.py`), parses the quote, fetches the Intel root CA, and verifies the signature chain.

## Skipped / Not Integrated

### nv-attentestation-sdk (nvtrust Python SDK)

- **Source:** [NVIDIA/nvtrust](https://github.com/NVIDIA/nvtrust)
- **Why skipped:** Pins `cryptography==43.0.1`, conflicts with Confidior's `cryptography>=48.0.0` (required for Ed25519 signing and DSSE). Cannot be added as a project dep without downgrading cryptography project-wide.
- **Workaround:** Usable via ephemeral environments (`uv run --no-project --with nv-attestation-sdk ...`) for one-off experiments. Not integrated into the verification pipeline.
- **Replacement:** `secretvm-verify` handles NVIDIA GPU attestation (JWT sig vs NVIDIA JWKS via NRAS) with no dep conflicts.

### nv-local-gpu-verifier

- Same `cryptography==43.0.1` conflict. Same workaround applies.

## Reference tools (docs-only, not runtime deps)

These are documented for hardware planning and CI workflows but are not project
dependencies. Reasons vary: they're firmware source repos (`AMDSEV`,
`intel/confidential-computing.tdx.tdx-module`), shell scripts (`canonical/tdx`),
C++ SDKs requiring compilation (`NVIDIA/attestation-sdk`), Go libraries
(`google/go-nvattest-tools`), or CI-only measurement calculators
(`sev-snp-measure`, `tdx-measure`).

## Boundary Statement

Confidior is an **evaluation engine**, not an attestation service. We consume `tdx-pytools` and `sev-pytools` as upstream parsing libraries. We do not operate a server, release keys, or compete with TEE-Attestation (TAS). Our value is the evidence graph, policy evaluator, and risk taxonomy layered on top.
