"""Measurement extraction and verification against a registry of known-good values."""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.core.taxonomy import EvidenceClass


@dataclass(frozen=True)
class MeasurementResult:
    workload: str
    platform: str
    actual_measurement: str
    expected_measurement: str
    match: bool
    source: str = ""
    source_url: str = ""
    error: str | None = None
    tcb_version: str | None = None


REGISTRY_SCHEMA_VERSION = 1


def load_registry(path: str | Path) -> dict[str, Any]:
    """Load a measurement registry YAML file and validate its schema version."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError("Registry must be a YAML dictionary")
    version = raw.get("version", 1)
    if version != REGISTRY_SCHEMA_VERSION:
        raise ValueError(f"Unsupported registry schema version: {version}")
    workloads = raw.get("workloads", {})
    if not isinstance(workloads, dict):
        raise ValueError("Registry workloads must be a dictionary")
    return workloads


def get_expected(workloads: dict[str, Any], workload: str) -> dict[str, Any]:
    entry = workloads.get(workload)
    if not isinstance(entry, dict):
        raise KeyError(f"Workload '{workload}' not found in registry")
    return entry


def evidence_class_for_workload(
    registry_path: str | Path, workload: str | None
) -> EvidenceClass:
    """The evidence class a registry entry states, or UNKNOWN when it states none.

    Registry-backed evidence carries its own provenance (``source``, and a
    ``verification`` line when the engine computed the value itself), so the
    grading path does not have to guess. A workload the registry does not hold
    is unknown rather than assumed.
    """
    if not workload:
        return EvidenceClass.UNKNOWN
    path = Path(registry_path)
    if not path.exists():
        return EvidenceClass.UNKNOWN
    try:
        entry = get_expected(load_registry(path), workload)
    except (KeyError, ValueError):
        return EvidenceClass.UNKNOWN
    return EvidenceClass.from_registry_entry(entry)


def extract_measurement(hex_data: str, platform: str) -> str:
    """Extract the attestation measurement (PCR0 / MR_TD) from raw hex data for a given platform."""
    raw = bytes.fromhex(hex_data.strip())

    if platform == "sevsnp":
        from sev_pytools.attestation_report import AttestationReport
        report = AttestationReport.unpack(raw)
        return bytes(report.measurement).hex()

    if platform == "tdx":
        from tdx_pytools import Quote
        quote = Quote.unpack(raw)
        return bytes(quote.body.mr_td).hex()

    if platform == "nitro":
        import cbor
        decoded = cbor.loads(raw)
        if isinstance(decoded, dict):
            payload = decoded.get("payload", b"")
            if isinstance(payload, bytes):
                payload = cbor.loads(payload)
        elif isinstance(decoded, list):
            payload = decoded[2] if len(decoded) > 2 else b""
            if isinstance(payload, bytes):
                try:
                    payload = cbor.loads(payload)
                except (ValueError, TypeError):
                    payload = {}
        else:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        pcr0 = (
        payload.get("pcr0", b"").hex()
        if isinstance(payload.get("pcr0"), bytes)
        else str(payload.get("pcr0", ""))
    )
        if not pcr0:
            pcrs = payload.get("pcrs")
            if isinstance(pcrs, dict):
                val = pcrs.get(0)
                if val is not None:
                    pcr0 = val.hex() if isinstance(val, bytes) else str(val)
        return pcr0 or "unknown"

    raise ValueError(f"Unknown platform: {platform}")


def extract_tcb_version(hex_data: str, platform: str) -> str | None:
    """Extract the TCB/firmware version from a quote, when the platform carries one.

    SEV-SNP and TDX quotes carry the TCB version; Nitro has no SVN concept
    (its temporal signal is the measurement match instead). Returns None for
    platforms without a TCB version.
    """
    raw = bytes.fromhex(hex_data.strip())

    if platform == "sevsnp":
        from sev_pytools.attestation_report import AttestationReport

        report = AttestationReport.unpack(raw)
        return (
            f"{report.current_tcb.bootloader}.{report.current_tcb.tee}."
            f"{report.current_tcb.snp}.{report.current_tcb.microcode}"
        )

    if platform == "tdx":
        from tdx_pytools import Quote

        quote = Quote.unpack(raw)
        svn: bytes = quote.body.tee_tcb_svn[:4]
        return svn.hex()

    return None


def verify_measurement(
    hex_data: str,
    platform: str,
    workload: str,
    registry_path: str | Path,
) -> MeasurementResult:
    """Compare a platform attestation measurement against a registry entry.

    Returns match + metadata.
    """
    workloads = load_registry(registry_path)
    try:
        entry = get_expected(workloads, workload)
    except KeyError as e:
        return MeasurementResult(
            workload=workload,
            platform=platform,
            actual_measurement="",
            expected_measurement="",
            match=False,
            error=str(e),
        )

    expected_platform = entry.get("platform", "")
    expected_measurement = entry.get("measurement", "")
    source = entry.get("source", "")
    source_url = entry.get("url", "")

    actual = extract_measurement(hex_data, platform)
    expected = expected_measurement.lower()

    platform_map = {
        "sevsnp": "AMD-SEV-SNP",
        "tdx": "Intel-TDX",
        "nitro": "AWS-Nitro",
        "nvidia": "NVIDIA-GPU-CC",
    }
    canonical_platform = platform_map.get(platform, platform.upper())
    if canonical_platform != expected_platform:
        return MeasurementResult(
            workload=workload,
            platform=platform,
            actual_measurement=actual,
            expected_measurement=expected,
            match=False,
            source=source,
            source_url=source_url,
            error=f"Platform mismatch: quote is {platform}, registry expects {expected_platform}",
        )

    match = actual.lower().rstrip("=") == expected.rstrip("=")

    return MeasurementResult(
        workload=workload,
        platform=platform,
        actual_measurement=actual,
        expected_measurement=expected,
        match=match,
        source=source,
        source_url=source_url,
        tcb_version=extract_tcb_version(hex_data, platform),
    )


# ---------------------------------------------------------------------------
# Measurement computation (Source C): wraps external tools.
# confidior measure --compute path. See docs/MEASUREMENT-CI-FINDINGS.md.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ComputeResult:
    platform: str
    tool: str
    status: str  # computed | blocked
    measurement: str = ""
    blocker: str = ""
    blocker_kind: str = ""
    command: str = ""


COMPUTE_FINDINGS: dict[str, dict[str, str]] = {
    "sevsnp": {
        "tool": "sev-snp-measure",
        "blocker": (
            "AWS EC2 SEV-SNP launch measurement is not independently reproducible: "
            "the OVMF used by EC2 (amazon-uefi) is not published. Captured measurement "
            "is the only reference."
        ),
        "blocker_kind": "non-public-firmware",
    },
    "tdx": {
        "tool": "tdx-measure",
        "blocker": (
            "tdx-measure is a Rust library/CLI; exact TDVF/kernel/initrd/cmdline from "
            "captured quotes are not recorded. Compute-only demo; validation lands Phase 1."
        ),
        "blocker_kind": "missing-artifacts",
    },
    "nitro": {
        "tool": "nitro-cli describe-eif",
        "blocker": (
            "Nitro PCR0 is deterministic given an EIF, but EIFs are not preserved and "
            "base images are unpinned. Reproducibility requires pinning the base image "
            "digest and preserving the EIF artifact."
        ),
        "blocker_kind": "missing-artifacts",
    },
}


def _find_tool(name: str) -> str | None:
    """Locate a CLI tool, preferring the current interpreter's venv bin dir."""
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    return shutil.which(name)


def compute_sevsnp(
    ovmf: str,
    kernel: str | None = None,
    initrd: str | None = None,
    append: str | None = None,
    vcpus: int = 1,
    vcpu_type: str = "EPYC-Milan",
    vmm_type: str = "ec2",
) -> ComputeResult:
    """Compute expected SEV-SNP launch measurement via sev-snp-measure."""
    tool = _find_tool("sev-snp-measure")
    if not tool:
        return ComputeResult(
            platform="sevsnp", tool="sev-snp-measure", status="blocked",
            blocker="sev-snp-measure not installed (pip install sev-snp-measure)",
            blocker_kind="tool-missing",
        )
    cmd = [tool, "--mode", "snp", "--vcpus", str(vcpus), "--vmm-type", vmm_type,
           "--vcpu-type", vcpu_type, "--ovmf", ovmf, "--output-format", "hex"]
    if kernel:
        cmd += ["--kernel", kernel]
    if initrd:
        cmd += ["--initrd", initrd]
    if append:
        cmd += ["--append", append]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return ComputeResult(
            platform="sevsnp", tool="sev-snp-measure", status="blocked",
            blocker=(proc.stderr or proc.stdout or f"tool exited {proc.returncode}").strip(),
            blocker_kind="tool-error", command=" ".join(cmd),
        )
    return ComputeResult(
        platform="sevsnp", tool="sev-snp-measure", status="computed",
        measurement=proc.stdout.strip(), command=" ".join(cmd),
    )


def compute_tdx() -> ComputeResult:
    """TDX compute path, blocked (library-only tool + unrecorded artifacts)."""
    f = COMPUTE_FINDINGS["tdx"]
    return ComputeResult(platform="tdx", tool=f["tool"], status="blocked",
                         blocker=f["blocker"], blocker_kind=f["blocker_kind"])


def compute_nitro(eif: str | None = None) -> ComputeResult:
    """Nitro compute path, blocked without a preserved EIF."""
    f = COMPUTE_FINDINGS["nitro"]
    if not eif:
        return ComputeResult(platform="nitro", tool=f["tool"], status="blocked",
                             blocker=f["blocker"], blocker_kind=f["blocker_kind"])
    tool = _find_tool("nitro-cli")
    if not tool:
        return ComputeResult(platform="nitro", tool=f["tool"], status="blocked",
                             blocker="nitro-cli not installed (aws-nitro-enclaves-cli)",
                             blocker_kind="tool-missing")
    cmd = [tool, "describe-eif", "--eif-path", eif]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return ComputeResult(platform="nitro", tool=f["tool"], status="blocked",
                             blocker=(proc.stderr or proc.stdout).strip(),
                             blocker_kind="tool-error", command=" ".join(cmd))
    return ComputeResult(platform="nitro", tool=f["tool"], status="computed",
                         measurement=proc.stdout.strip(), command=" ".join(cmd))
