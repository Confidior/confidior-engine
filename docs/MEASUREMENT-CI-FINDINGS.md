# Measurement CI: Reproducibility Findings

**Date:** 2026-08-13
**Status:** Compute mechanism built; computed-vs-captured MATCH blocked by external factors
**Tooling:** `scripts/compute_measurement.py` (wraps `sev-snp-measure`, `tdx-measure`, `nitro-cli`)

## Summary

The goal of this work was to compute *expected* attestation measurements from VM
configuration and compare them against the *captured* measurements in the
registry (Source B → C upgrade). The compute mechanism works. A
computed-vs-captured MATCH is **not achievable for any of the three platforms**
each is blocked by an external factor, not by the engine. These blockers are
themselves the finding: they define the limits of independent verifiability,
which is exactly what an honest grader must report.

## Findings

### 1. SEV-SNP (AWS c6a): blocked: non-public firmware

**Target:** `507e82d2…a15f` (captured 2026-07-08, `aws-c6a-sev-snp`)

The SEV-SNP launch measurement is SHA-384 over (OVMF hash, VMSA, kernel hash,
initrd hash, cmdline). `sev-snp-measure` (virtee, PyPI, Apache-2.0) computes it
correctly, verified working with `--vmm-type ec2` (2026-08-13). The blocker is
the **OVMF**: EC2 uses `amazon-uefi`, which AWS does not publish. Without the
exact firmware, the expected value cannot be computed.

**Implication:** EC2 SEV-SNP customers cannot independently verify the launch
measurement. The captured measurement is the only reference, they must trust
AWS's measurement, not verify it. This is a real verifiability limit, not an
engine limitation.

**Unblock:** AWS publishes `amazon-uefi` (or a measurement-relevant OVMF hash).

### 2. Nitro (AWS c6g): blocked: unpinned base image + unpreserved EIF

**Target:** `cca6d8f3…362a` (captured 2026-07-08, `aws-c6g-nitro`)

Nitro PCR0 is deterministic given an EIF (`nitro-cli describe-eif` computes it
without booting). The blocker is the **EIF itself**: the EIF for the captured
quote (`aws-samples/sample-nitro-enclaves-attestation`) was not preserved, and
the sample repo's base image is unpinned (`FROM python:3.9-slim`). An EIF
rebuilt today would have a different PCR0, the tag has moved since July 2026.

**Implication:** Nitro reproducibility requires (a) pinning the base image
digest and (b) preserving the EIF artifact alongside the quote. Without both,
historical PCR0s drift and cannot be recomputed.

**Unblock:** pin base image digest; store EIF with each capture.

### 3. TDX: blocked: library-only tool + unrecorded artifacts

**Target:** `b65ea009…f71b` (captured quote in fixtures)

`tdx-measure` (virtee, GitHub, MIT OR Apache-2.0) is a **Rust library with no
CLI binary** as of 2026-08-13 (v0.1.0, 12 stars), the earlier "fork of
dstack-mr" description was inaccurate. Computing MRTD/RTMR0-3 requires a Rust
wrapper. Additionally, the exact TDVF/kernel/initrd/cmdline from the captured
quote are not recorded, so a computed-vs-captured comparison is impossible for
the existing quote.

**Implication:** TDX compute-only demo now; validation planned later. The tool needs a CLI wrapper and the capture process needs to
record artifacts.

## Update 2026-08-13: vendor verification results

Two vendor-verification results landed:

### Tinfoil: computed-vs-published MATCH (4/4 platforms)

Independently reproduced Tinfoil's published TDX measurements
(`hardware-measurements` repo, v0.0.40): built `tdx-measure-tinfoil` CLI from
source (aarch64), used podman as a docker shim (their tool needs docker for
ACPI generation), ran `measure.py` with the pinned OVMF
(`ovmf_2025.02-3ubuntu2_all.deb`). Computed MRTD + RTMR0 are **byte-identical**
to published values for `medium_1d_new`, `large_1d_new`, `extra_large_1d_new`,
`medium_0d_new`. Evidence: `data/vendor-evidence/tinfoil/verdict.json`.

**Caveat:** this used Tinfoil's own toolchain (their measure.py + tdx-measure),
not Confidior's engine. It proves their published measurements are reproducible;
it does not exercise the engine.

### RedPill: engine verified a real production TDX quote end-to-end

Fetched a real TDX attestation report from RedPill's public
`/v1/attestation/report` endpoint (their production gateway, dstack/TDX infra):

- `confidior verify` → **ALLOW, Level 2, HIGH, 51/100 (D)**,
  **Rekor anchored** (index=3143333764)
- `confidior measure` → **MATCH** (MRTD `f06dfda6…` extracted by engine vs
  registry entry `redpill-gateway-tdx`)

This is the engine doing its actual job, crypto verify, risk grade, policy
evaluation, badge + bundle, Rekor, on real production vendor evidence.

### `confidior measure --compute` integration

Compute logic moved into the engine (`src/export/measurement.py`):
`compute_sevsnp` (wraps sev-snp-measure), `compute_tdx`/`compute_nitro`
(honest-finding blockers). CLI wired: `confidior measure --compute
--platform sevsnp --ovmf OVMF.fd` → COMPUTED; `--platform tdx` → BLOCKED +
honest finding. Seamless pipeline: compute → capture → verify → grade →
evidence, one CLI.

## Unblock plan, 2026-10-18

An earlier reading of this document said computed-vs-captured was blocked on all
three platforms and that artifact binding therefore could not be demonstrated
anywhere. **That was wrong**, and the same file contains the disproof: Tinfoil
reproduced 4/4 platforms byte-identically and RedPill's production TDX quote
matched through the engine. The distinction:

| Case | Status | Cause |
|---|---|---|
| Tinfoil TDX, 4 platforms | **MATCH** | Their measurement publication pins the OVMF and the toolchain |
| RedPill TDX gateway | **MATCH** through the engine | A live quote compared against a registry baseline |
| TDX, historical fixture | blocked | *Our* capture did not record TDVF/kernel/initrd/cmdline |
| Nitro, historical fixture | blocked | *Our* capture did not preserve the EIF; base image unpinned |
| SEV-SNP, AWS c6a | genuinely blocked | AWS does not publish `amazon-uefi` |

So two of three blockers are self-inflicted capture omissions, not platform
impossibilities, and one is external.

### 1. TDX — wrap the tool, then record the artifacts

`compute_tdx()` is a stub returning a hardcoded blocker, but the toolchain is
known to work: Tinfoil's `tdx-measure-tinfoil` was built from source and produced
byte-identical MRTD/RTMR0 for four platforms. Either wrap `tdx-measure` in a
Rust shim, or vendor Tinfoil's CLI. The blocker that remains is *input*: a TDX
MRTD cannot be recomputed without the TDVF, kernel, initrd and cmdline, so the
capture step must record them.

**Action:** wrap the tool; add TDVF/kernel/initrd/cmdline to the capture
checklist; re-capture one workload with all four recorded to prove the loop
closes.

### 2. Nitro — pin, then preserve

PCR0 is deterministic given an EIF. `nitro-cli describe-eif` computes it without
booting. `compute_nitro(eif=...)` already supports this path and only reports
blocked when no EIF is supplied.

**Action:** pin the base image by digest; store the EIF alongside every capture.
No tooling work required.

### 3. SEV-SNP — external, and the honest position

`compute_sevsnp` works; the AWS fixture fails because the OVMF is not public.
Nothing to build. Record it as a verifiability limit of that vendor's offering,
which is a finding in its own right and belongs in the grade rather than in a
todo list.

### Why this order matters

Artifact binding ("the thing that was verified is the thing running") needs one
platform where compute and capture agree. RedPill already demonstrates the
comparison half through the engine. Completing TDX or Nitro closes the loop and
makes the producer-side verification note demonstrable rather than theoretical.

## Next steps

- [ ] **TDX**: wrap `tdx-measure` (or vendor Tinfoil's CLI); record TDVF/kernel/initrd/cmdline in the capture
- [ ] **Nitro**: pin base image digest + preserve EIF (no tooling work)
- [ ] **SEV-SNP on AWS**: cannot be unblocked by us; record as a vendor verifiability limit in the grade
- [ ] Prove one platform end to end: compute → capture → match, all artifacts preserved
- [ ] Decide: publish findings as a dev blog post
- [ ] Phala reproduction via `dstack-mr` + `meta-dstack` + on-chain contracts
- [ ] Remaining vendors: PrivateMode, VoltageGPU, Maple Chat (locate measurement publications)
