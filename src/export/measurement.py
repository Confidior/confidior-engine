"""Measurement extraction and verification against a registry of known-good values."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


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
        pcr0 = payload.get("pcr0", b"").hex() if isinstance(payload.get("pcr0"), bytes) else str(payload.get("pcr0", ""))
        if not pcr0:
            pcrs = payload.get("pcrs")
            if isinstance(pcrs, dict):
                val = pcrs.get(0)
                if val is not None:
                    pcr0 = val.hex() if isinstance(val, bytes) else str(val)
        return pcr0 or "unknown"

    raise ValueError(f"Unknown platform: {platform}")


def verify_measurement(
    hex_data: str,
    platform: str,
    workload: str,
    registry_path: str | Path,
) -> MeasurementResult:
    """Compare a platform attestation measurement against a registry entry. Returns match + metadata."""
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
    )
