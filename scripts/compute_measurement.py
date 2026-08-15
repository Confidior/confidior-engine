#!/usr/bin/env python3
"""Compute expected attestation measurements for confidential-computing platforms.

Wraps three tools:

  * SEV-SNP:  `sev-snp-measure` (virtee, PyPI, Apache-2.0) — computes the expected
              launch measurement from OVMF/kernel/initrd/cmdline. `--vmm-type ec2`
              supported. WORKING (verified 2026-08-13).
  * TDX:      `tdx-measure` (virtee, GitHub, MIT/Apache-2.0) — computes MRTD +
              RTMR0-3 from TDVF config/kernel/initrd/cmdline. LIBRARY-ONLY as of
              2026-08-13 (no CLI binary); requires a Rust wrapper. Compute-only
              demo in Phase 0; validation lands Phase 1.
  * Nitro:    `nitro-cli describe-eif` (AWS) — computes PCR0/PCR1/PCR2 from an EIF
              without booting. Requires an EIF file (built via docker +
              aws-nitro-enclaves-cli). NOT AVAILABLE in this environment
              (no docker, no EIF artifact).

Honest-finding mode: when a platform's expected value cannot be independently
computed (missing artifacts, non-public firmware), the script reports the
blocker instead of fabricating a value. This is the "unreproducible → publish
as honest finding" path from the roadmap.

Usage:
    python scripts/compute_measurement.py sevsnp --ovmf OVMF.fd \
        [--kernel vmlinuz --initrd initrd.img --append "cmdline"] \
        [--vcpu-type EPYC-Milan] [--vcpus 1] [--vmm-type ec2]
    python scripts/compute_measurement.py tdx --tdvf TDVF.fd \
        [--kernel vmlinuz --initrd initrd.img --append "cmdline"]
    python scripts/compute_measurement.py nitro --eif enclave.eif
    python scripts/compute_measurement.py --check-registry data/registry.yaml
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Findings registry: what we know about reproducibility per platform.
# Updated 2026-08-13 from hands-on verification.
# ---------------------------------------------------------------------------

FINDINGS: dict[str, dict[str, Any]] = {
    "sevsnp": {
        "tool": "sev-snp-measure",
        "tool_status": "working",
        "tool_source": "https://pypi.org/project/sev-snp-measure/ (virtee, Apache-2.0)",
        "blocker": (
            "AWS EC2 SEV-SNP launch measurement is not independently reproducible: "
            "the OVMF used by EC2 (amazon-uefi) is not published. The measurement is "
            "SHA-384 over (OVMF hash, VMSA, kernel hash, initrd hash, cmdline); without "
            "the exact OVMF the expected value cannot be computed. Captured measurement "
            "is the only reference — EC2 customers must trust AWS's measurement, not "
            "verify it independently."
        ),
        "blocker_kind": "non-public-firmware",
        "verified": "2026-08-13",
    },
    "tdx": {
        "tool": "tdx-measure",
        "tool_status": "library-only",
        "tool_source": "https://github.com/virtee/tdx-measure (MIT OR Apache-2.0)",
        "blocker": (
            "tdx-measure is a Rust library with no CLI binary as of 2026-08-13 "
            "(12 stars, v0.1.0). Computing MRTD/RTMR0-3 requires a Rust wrapper. "
            "Additionally, the exact TDVF/kernel/initrd/cmdline from the captured "
            "TDX quote are not recorded, so a computed-vs-captured comparison is "
            "not possible for the existing quote. Compute-only demo in Phase 0; "
            "validation lands Phase 1."
        ),
        "blocker_kind": "missing-artifacts",
        "verified": "2026-08-13",
    },
    "nitro": {
        "tool": "nitro-cli describe-eif",
        "tool_status": "not-available",
        "tool_source": "https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli.html",
        "blocker": (
            "Nitro PCR0 is deterministic given an EIF, but the EIF for the captured "
            "quote (aws-samples/sample-nitro-enclaves-attestation, captured 2026-07-08) "
            "was not preserved, and the sample repo's base image is unpinned "
            "(FROM python:3.9-slim), so an EIF rebuilt today would have a different "
            "PCR0. Reproducibility requires pinning the base image digest and "
            "preserving the EIF artifact."
        ),
        "blocker_kind": "missing-artifacts",
        "verified": "2026-08-13",
    },
}


@dataclass
class ComputeResult:
    platform: str
    tool: str
    status: str  # computed | blocked
    measurement: str = ""
    blocker: str = ""
    blocker_kind: str = ""
    command: str = ""


def _find_tool(name: str) -> str | None:
    """Locate a CLI tool, preferring the current interpreter's venv bin dir."""
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    return shutil.which(name)


def _run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return proc.returncode, (proc.stdout or proc.stderr).strip()


def compute_sevsnp(args: argparse.Namespace) -> ComputeResult:
    tool = _find_tool("sev-snp-measure")
    if not tool:
        return ComputeResult(
            platform="sevsnp",
            tool="sev-snp-measure",
            status="blocked",
            blocker="sev-snp-measure not installed (pip install sev-snp-measure)",
            blocker_kind="tool-missing",
        )
    cmd = [
        tool,
        "--mode", "snp",
        "--vcpus", str(args.vcpus),
        "--vmm-type", args.vmm_type,
        "--vcpu-type", args.vcpu_type,
        "--ovmf", str(args.ovmf),
        "--output-format", "hex",
    ]
    if args.kernel:
        cmd += ["--kernel", str(args.kernel)]
    if args.initrd:
        cmd += ["--initrd", str(args.initrd)]
    if args.append:
        cmd += ["--append", args.append]
    rc, out = _run(cmd)
    if rc != 0:
        return ComputeResult(
            platform="sevsnp",
            tool="sev-snp-measure",
            status="blocked",
            blocker=out or f"tool exited {rc}",
            blocker_kind="tool-error",
            command=" ".join(cmd),
        )
    return ComputeResult(
        platform="sevsnp",
        tool="sev-snp-measure",
        status="computed",
        measurement=out,
        command=" ".join(cmd),
    )


def compute_tdx(args: argparse.Namespace) -> ComputeResult:
    # tdx-measure is library-only; no CLI. Report the blocker with the
    # mechanism documented. A Rust wrapper is the Phase 1 path.
    f = FINDINGS["tdx"]
    return ComputeResult(
        platform="tdx",
        tool="tdx-measure",
        status="blocked",
        blocker=f["blocker"],
        blocker_kind=f["blocker_kind"],
    )


def compute_nitro(args: argparse.Namespace) -> ComputeResult:
    f = FINDINGS["nitro"]
    if not args.eif:
        return ComputeResult(
            platform="nitro",
            tool="nitro-cli describe-eif",
            status="blocked",
            blocker=f["blocker"],
            blocker_kind=f["blocker_kind"],
        )
    tool = _find_tool("nitro-cli")
    if not tool:
        return ComputeResult(
            platform="nitro",
            tool="nitro-cli describe-eif",
            status="blocked",
            blocker="nitro-cli not installed (aws-nitro-enclaves-cli)",
            blocker_kind="tool-missing",
        )
    cmd = [tool, "describe-eif", "--eif-path", str(args.eif)]
    rc, out = _run(cmd)
    if rc != 0:
        return ComputeResult(
            platform="nitro",
            tool="nitro-cli describe-eif",
            status="blocked",
            blocker=out or f"tool exited {rc}",
            blocker_kind="tool-error",
            command=" ".join(cmd),
        )
    return ComputeResult(
        platform="nitro",
        tool="nitro-cli describe-eif",
        status="computed",
        measurement=out,
        command=" ".join(cmd),
    )


def check_registry(path: str) -> int:
    """Report which registry entries have computed (Source C) vs captured (Source B) values."""
    import yaml

    workloads = yaml.safe_load(Path(path).read_text()).get("workloads", {})
    print(f"Registry: {path}")
    print(f"{'workload':<22} {'source':<16} measurement")
    for name, entry in workloads.items():
        src = entry.get("source", "?")
        meas = entry.get("measurement", "")[:16] + "…" if entry.get("measurement") else "(none)"
        print(f"{name:<22} {src:<16} {meas}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="platform", required=True)

    snp = sub.add_parser("sevsnp", help="Compute expected SEV-SNP launch measurement")
    snp.add_argument("--ovmf", required=True, help="OVMF firmware file")
    snp.add_argument("--kernel", help="Kernel file (vmlinuz)")
    snp.add_argument("--initrd", help="Initrd file")
    snp.add_argument("--append", help="Kernel command line")
    snp.add_argument("--vcpus", type=int, default=1)
    snp.add_argument("--vcpu-type", default="EPYC-Milan")
    snp.add_argument("--vmm-type", default="ec2")

    tdx = sub.add_parser("tdx", help="Compute expected TDX MRTD (library-only; blocked)")
    tdx.add_argument("--tdvf", help="TDVF firmware file (unused until CLI exists)")

    nitro = sub.add_parser("nitro", help="Compute Nitro PCR0 from EIF")
    nitro.add_argument("--eif", help="EIF file path")

    sub.add_parser("check-registry", help="Report registry entry sources")

    args = parser.parse_args()

    if args.platform == "check-registry":
        registry = getattr(args, "registry", None) or "data/registry.yaml"
        return check_registry(registry)

    if args.platform == "sevsnp":
        result = compute_sevsnp(args)
    elif args.platform == "tdx":
        result = compute_tdx(args)
    elif args.platform == "nitro":
        result = compute_nitro(args)
    else:
        parser.error(f"unknown platform {args.platform}")

    print(json.dumps(asdict(result), indent=2))
    return 0 if result.status == "computed" else 1


if __name__ == "__main__":
    sys.exit(main())
