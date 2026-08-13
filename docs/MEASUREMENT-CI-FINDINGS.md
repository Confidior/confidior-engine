# Measurement CI — Reproducibility Findings

**Date:** 2026-08-13
**Status:** Compute mechanism built; computed-vs-captured MATCH blocked by external factors
**Tooling:** `scripts/compute_measurement.py` (wraps `sev-snp-measure`, `tdx-measure`, `nitro-cli`)

## Summary

The goal of this work was to compute *expected* attestation measurements from VM
configuration and compare them against the *captured* measurements in the
registry (Source B → C upgrade). The compute mechanism works. A
computed-vs-captured MATCH is **not achievable for any of the three platforms**
— each is blocked by an external factor, not by the engine. These blockers are
themselves the finding: they define the limits of independent verifiability,
which is exactly what an honest grader must report.

## Findings

### 1. SEV-SNP (AWS c6a) — blocked: non-public firmware

**Target:** `507e82d2…a15f` (captured 2026-07-08, `aws-c6a-sev-snp`)

The SEV-SNP launch measurement is SHA-384 over (OVMF hash, VMSA, kernel hash,
initrd hash, cmdline). `sev-snp-measure` (virtee, PyPI, Apache-2.0) computes it
correctly — verified working with `--vmm-type ec2` (2026-08-13). The blocker is
the **OVMF**: EC2 uses `amazon-uefi`, which AWS does not publish. Without the
exact firmware, the expected value cannot be computed.

**Implication:** EC2 SEV-SNP customers cannot independently verify the launch
measurement. The captured measurement is the only reference — they must trust
AWS's measurement, not verify it. This is a real verifiability limit, not an
engine limitation.

**Unblock:** AWS publishes `amazon-uefi` (or a measurement-relevant OVMF hash).

### 2. Nitro (AWS c6g) — blocked: unpinned base image + unpreserved EIF

**Target:** `cca6d8f3…362a` (captured 2026-07-08, `aws-c6g-nitro`)

Nitro PCR0 is deterministic given an EIF (`nitro-cli describe-eif` computes it
without booting). The blocker is the **EIF itself**: the EIF for the captured
quote (`aws-samples/sample-nitro-enclaves-attestation`) was not preserved, and
the sample repo's base image is unpinned (`FROM python:3.9-slim`). An EIF
rebuilt today would have a different PCR0 — the tag has moved since July 2026.

**Implication:** Nitro reproducibility requires (a) pinning the base image
digest and (b) preserving the EIF artifact alongside the quote. Without both,
historical PCR0s drift and cannot be recomputed.

**Unblock:** pin base image digest; store EIF with each capture.

### 3. TDX — blocked: library-only tool + unrecorded artifacts

**Target:** `b65ea009…f71b` (captured quote in fixtures)

`tdx-measure` (virtee, GitHub, MIT OR Apache-2.0) is a **Rust library with no
CLI binary** as of 2026-08-13 (v0.1.0, 12 stars) — the earlier "fork of
dstack-mr" description was inaccurate. Computing MRTD/RTMR0-3 requires a Rust
wrapper. Additionally, the exact TDVF/kernel/initrd/cmdline from the captured
quote are not recorded, so a computed-vs-captured comparison is impossible for
the existing quote.

**Implication:** TDX compute-only demo now; validation planned later. The tool needs a CLI wrapper and the capture process needs to
record artifacts.

## Next steps

- [ ] Revisit when AWS publishes `amazon-uefi` (SEV-SNP unblock)
- [ ] Pin base image digest + preserve EIF on future Nitro captures
- [ ] Rust wrapper for `tdx-measure` (planned)
- [ ] Decide: publish findings as a dev blog post
