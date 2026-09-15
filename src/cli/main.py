"""CLI entry point with subcommands for verify, measure, and freshness checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.core.attacks import compute_attack_db_snapshot
from src.core.policy import evaluate, load_policy
from src.core.risk import compute_assurance_level, set_archaeology_db_path
from src.core.taxonomy import EvidenceBundle, EvidenceGraph, ThreatModelTier
from src.export.badge import (
    extract_badge_attributes,
    generate_badge_svg,
    verify_badge,
)
from src.export.c5 import evaluate_c5_compliance, generate_c5_report
from src.export.display import badge_dims, explain_lines, report_items
from src.export.dsse import (
    create_signed_bundle,
    load_or_create_keypair,
)
from src.export.measurement import verify_measurement
from src.tools.cve_sync import find_affected_bundles, sync_cves
from src.tools.cve_tcb_mapper import map_cve_tcb_for_db

ADAPTERS = {
    "tdx": ("src.ingest.adapters.tdx", "parse_tdx_quote", "verify_tdx_quote"),
    "sevsnp": ("src.ingest.adapters.sevsnp", "parse_sevsnp_report", "verify_sevsnp_report"),
    "nitro": ("src.ingest.adapters.nitro", "parse_nitro_attestation", "verify_nitro_attestation"),
    "nvidia": (
        "src.ingest.adapters.nvidia",
        "parse_nvidia_gpu_attestation",
        "verify_nvidia_gpu_attestation",
    ),
}


def _load_adapter(platform: str):
    module_path, func_name, _ = ADAPTERS[platform]
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, func_name)


def _load_verify_fn(platform: str):
    module_path, _, verify_fn = ADAPTERS[platform]
    if not verify_fn:
        return None
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, verify_fn)


def detect_platform(hex_data: str) -> str:
    raw = bytes.fromhex(hex_data.strip())
    # Try CBOR (Nitro)
    try:
        import cbor

        decoded = cbor.loads(raw)
        if isinstance(decoded, (list, dict)):
            return "nitro"
    except Exception:
        pass
    # Try SEV-SNP (1184 bytes, versioned struct)
    try:
        from sev_pytools.attestation_report import AttestationReport

        report = AttestationReport.unpack(raw)
        if report.version >= 1:
            return "sevsnp"
    except Exception:
        pass
    # Try TDX
    try:
        from tdx_pytools import Quote

        quote = Quote.unpack(raw)
        if quote.header.version == 4:
            return "tdx"
    except Exception:
        pass
    raise ValueError("Could not detect platform. Try --platform tdx|sevsnp|nitro")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse args and dispatch to verify, measure, or freshness subcommands."""
    parser = argparse.ArgumentParser(
        prog="confidior",
        description="Honest assurance engine for confidential computing",
    )
    sub = parser.add_subparsers(dest="command")

    verify = sub.add_parser("verify", help="Verify attestation evidence against a policy")
    verify.add_argument("--input", required=True, help="Path to raw attestation data (hex file)")
    verify.add_argument(
        "--platform",
        choices=list(ADAPTERS.keys()),
        help="TEE platform (auto-detected if omitted)",
    )
    verify.add_argument("--policy", required=True, help="Path to policy YAML file")
    verify.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output files (default: current directory)",
    )
    verify.add_argument("--workload", default="unknown", help="Workload identifier")
    verify.add_argument(
        "--fmspc",
        default=None,
        help="Intel platform FMSPC (6-byte hex, e.g. 50806f000000). Required for "
        "the live TCB lookup on Intel TDX; comes from the PCK certificate chain, "
        "which the engine does not extract automatically yet.",
    )
    verify.add_argument(
        "--threat-model",
        default="cloud-admin",
        choices=["software-operator", "cloud-admin", "physical-host", "nation-state-physical"],
        help="Threat model under which the evidence is graded. Software-only "
        "models exclude physical-layer attacks; physical-capable models include "
        "them. The same evidence grades differently per threat model.",
    )
    verify.add_argument(
        "--verify",
        action="store_true",
        help="Cryptographically verify the attestation signature chain "
        "(requires network access to Intel PCS / AMD KDS / AWS root CA)",
    )
    verify.add_argument(
        "--product",
        default="genoa",
        choices=["milan", "genoa", "turin"],
        help="SEV-SNP processor product for cert chain verification "
        "(default: genoa; only used with --verify)",
    )
    verify.add_argument(
        "--vlek-cert",
        default=None,
        type=Path,
        help="Path to VLEK certificate (PEM) for SEV-SNP verification on AWS. "
        "When provided, skips VCEK KDS lookup and uses the local VLEK cert "
        "with a chain fetched from AMD KDS.",
    )
    verify.add_argument(
        "--key-path",
        default=None,
        help="Path to operator's persistent Ed25519 keypair (JSON). Created if missing. "
        "Without this flag, an ephemeral key is used and the bundle's signer is "
        "not reproducible across runs (see docs/TRUST-MODEL.md).",
    )
    verify.add_argument(
        "--no-rekor",
        action="store_true",
        help="Skip Rekor anchoring. Default: anchor to public Rekor log and embed "
        "inclusion proof in the bundle.",
    )
    verify.add_argument(
        "--score-profile",
        default="default",
        choices=["default", "finance", "gpu-tee"],
        help="Scoring profile: default (balanced), finance (trust/freshness weighted), "
        "gpu-tee (trust/threat weighted).",
    )

    measure = sub.add_parser(
        "measure", help="Compare attestation measurement against expected value"
    )
    measure.add_argument("--input", help="Path to raw attestation data (hex file)")
    measure.add_argument(
        "--platform", required=True, choices=list(ADAPTERS.keys()), help="TEE platform"
    )
    measure.add_argument("--workload", help="Workload identifier (must exist in registry)")
    measure.add_argument("--registry", help="Path to measurement registry YAML file")
    measure.add_argument(
        "--tcb",
        help="TCB/firmware version of the quote (e.g. 0.0.1.18); enables the CVE lag check",
    )
    measure.add_argument(
        "--db-path",
        default="data/archaeology.db",
        help="Path to archaeology SQLite DB (for --tcb lag check)",
    )
    measure.add_argument(
        "--compute",
        action="store_true",
        help=(
            "Compute expected measurement from VM config (Source C) "
            "instead of verifying a quote"
        ),
    )
    measure.add_argument("--ovmf", help="[--compute sevsnp] OVMF firmware file")
    measure.add_argument("--kernel", help="[--compute sevsnp] kernel file")
    measure.add_argument("--initrd", help="[--compute sevsnp] initrd file")
    measure.add_argument("--append", help="[--compute sevsnp] kernel command line")
    measure.add_argument("--vcpus", type=int, default=1, help="[--compute sevsnp] guest vcpus")
    measure.add_argument(
        "--vcpu-type",
        default="EPYC-Milan",
        help="[--compute sevsnp] guest vcpu type",
    )
    measure.add_argument(
        "--vmm-type",
        default="ec2",
        help="[--compute sevsnp] vmm type (QEMU, ec2, gce)",
    )
    measure.add_argument("--eif", help="[--compute nitro] EIF file path")

    freshness = sub.add_parser(
        "freshness", help="Check whether an evidence bundle's attack DB snapshot is current"
    )
    freshness.add_argument("--input", required=True, help="Path to evidence_bundle.json")
    freshness.add_argument("--verbose", action="store_true", help="Show attack count details")

    verify_badge_cmd = sub.add_parser(
        "verify-badge", help="Verify a badge commitment is bound to a bundle signature"
    )
    verify_badge_cmd.add_argument(
        "--from-fixture",
        type=Path,
        help=(
            "Path to a verify-badge fixture directory containing "
            "badge.svg and manifest.json. Auto-loads commitment from "
            "the SVG and bundle signature from the manifest. "
            "Overrides --badge-svg / --commitment / --signature."
        ),
    )
    verify_badge_cmd.add_argument(
        "--badge-svg",
        type=Path,
        help="Path to badge SVG; extracts commitment, bundle_id, level, and dimensions",
    )
    verify_badge_cmd.add_argument("--commitment", help="Badge data-commitment value")
    verify_badge_cmd.add_argument("--bundle-id", help="Bundle ID")
    verify_badge_cmd.add_argument("--level", type=int, help="Assurance level number")
    verify_badge_cmd.add_argument("--signature", help="Bundle signature hex")
    verify_badge_cmd.add_argument(
        "--dimension",
        action="append",
        default=[],
        help=(
            "Dimension key=value used in the commitment (repeatable). "
            "Ignored if --badge-svg is used."
        ),
    )

    attacks_cmd = sub.add_parser("attacks", help="Manage the attack database")
    attacks_sub = attacks_cmd.add_subparsers(dest="attacks_command")
    attacks_map = attacks_sub.add_parser(
        "map-cve-tcb", help="Map CVE IDs to TCB/firmware fix versions"
    )
    attacks_map.add_argument(
        "--db-path", default="data/archaeology.db", help="Path to archaeology SQLite DB"
    )
    attacks_map.add_argument(
        "--dry-run", action="store_true", help="Show mappings without updating DB"
    )

    attacks_sync = attacks_sub.add_parser(
        "sync", help="Sync CVEs from OpenCVE or NVD and optionally re-score bundles"
    )
    attacks_sync.add_argument(
        "--source",
        choices=["opencve", "nvd"],
        default="opencve",
        help="CVE source (default: opencve; nvd = free, no credentials)",
    )
    attacks_sync.add_argument(
        "--db-path", default="data/archaeology.db", help="Path to archaeology SQLite DB"
    )
    attacks_sync.add_argument(
        "--bundle-dir", help="Directory of evidence_bundle.json files to re-score"
    )
    attacks_sync.add_argument(
        "--output-dir", default=".", help="Directory for re-scored bundle reports"
    )
    attacks_sync.add_argument(
        "--max-pages", type=int, default=3, help="Max pages per vendor/product (OpenCVE)"
    )
    attacks_sync.add_argument(
        "--dry-run", action="store_true", help="Print what would be added, don't insert"
    )

    if argv is None:
        argv = sys.argv[1:]
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "measure":
        return _cmd_measure(args)
    if args.command == "freshness":
        return _cmd_freshness(args)
    if args.command == "verify-badge":
        return _cmd_verify_badge(args)
    if args.command == "attacks":
        if args.attacks_command == "map-cve-tcb":
            return _cmd_attacks_map_cve_tcb(args)
        if args.attacks_command == "sync":
            return _cmd_attacks_sync(args)
        attacks_cmd.print_help()
        return 0

    return 0


def _print_measure_result(result) -> None:
    print(f"  Workload:      {result.workload}")
    print(f"  Platform:      {result.platform}")
    print(f"  Actual:        0x{result.actual_measurement[:48]}...")
    print(f"  Expected:      0x{result.expected_measurement[:48]}...")
    if result.source:
        print(
            f"  Source:        {result.source} ({result.source_url})"
            if result.source_url
            else f"  Source:        {result.source}"
        )
    if result.error:
        print(f"  Error:         {result.error}")
        print(f"  {_color('Result:       MISMATCH', _DECISION_COLORS['DENY'])}")
    elif result.match:
        print(f"  {_color('Result:       MATCH', _DECISION_COLORS['ALLOW'])}")
    else:
        print(f"  {_color('Result:       MISMATCH', _DECISION_COLORS['DENY'])}")


def _cmd_measure(args) -> int:
    if args.compute:
        return _cmd_measure_compute(args)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    registry_path = Path(args.registry)
    if not registry_path.exists():
        print(f"Error: registry file not found: {registry_path}", file=sys.stderr)
        return 1

    hex_data = input_path.read_text()

    result = verify_measurement(
        hex_data=hex_data,
        platform=args.platform,
        workload=args.workload,
        registry_path=registry_path,
    )

    if result.error:
        print(f"\n  {_color('ERROR', _DECISION_COLORS['DENY'])}: {result.error}\n")
        _print_measure_result(result)
        return 1

    _print_measure_result(result)
    rc = 0 if result.match else 1

    tcb = args.tcb or result.tcb_version
    if tcb:
        rc = _report_tcb_lag(args, tcb) or rc
    return rc


def _report_tcb_lag(args, tcb: str) -> int:
    """Cross-reference the quote's TCB version against CVE records."""
    """Cross-reference the quote's TCB version against CVE records (task 11)."""
    from src.core.taxonomy import Platform
    from src.tools.cve_tcb_mapper import check_tcb_lag

    db_path = Path(args.db_path)
    if not db_path.exists():
        print(
            f"\n  {_color('TCB check skipped', _DECISION_COLORS['DENY'])}: "
            f"archaeology DB not found at {db_path} "
            "(run `confidior attacks sync` first)"
        )
        return 0

    platform_map = {"sevsnp": "AMDSEVSNP", "tdx": "IntelTDX", "nitro": "AWSNitro"}
    platform_name = platform_map.get(args.platform)
    if platform_name is None:
        return 0
    platform = Platform[platform_name]

    from src.tools.archaeology import ArchaeologyDB
    db = ArchaeologyDB(db_path=db_path)
    try:
        lag = check_tcb_lag(db, platform, tcb)
    finally:
        db.close()

    if not lag:
        print(
            f"\n  {_color('TCB: up to date', _DECISION_COLORS['ALLOW'])} — "
            f"no known unpatched CVEs for {platform.value} at TCB {tcb}"
        )
        return 0

    print(
        f"\n  {_color('TCB: N months behind', _DECISION_COLORS['DENY'])} — "
        f"{len(lag)} unpatched CVE(s) at TCB {tcb}:"
    )
    for v in sorted(lag, key=lambda x: x.months_behind or 0, reverse=True):
        lag_str = f"{v.months_behind:.0f} months" if v.months_behind is not None else "age unknown"
        print(
            f"    - {v.cve_id} [{v.attack_name}] "
            f"fixed in {v.fixed_version} — {lag_str} behind"
        )
    return 1


def _cmd_measure_compute(args) -> int:
    """Compute expected measurement from VM config (Source C) via external tools."""
    from src.export.measurement import compute_nitro, compute_sevsnp, compute_tdx

    if args.platform == "sevsnp":
        if not args.ovmf:
            print("Error: --ovmf required for --compute sevsnp", file=sys.stderr)
            return 1
        result = compute_sevsnp(
            ovmf=args.ovmf, kernel=args.kernel, initrd=args.initrd, append=args.append,
            vcpus=args.vcpus, vcpu_type=args.vcpu_type, vmm_type=args.vmm_type,
        )
    elif args.platform == "tdx":
        result = compute_tdx()
    elif args.platform == "nitro":
        result = compute_nitro(args.eif)
    else:
        print(f"Error: --compute not supported for platform {args.platform}", file=sys.stderr)
        return 1

    print(f"  Platform:      {result.platform}")
    print(f"  Tool:          {result.tool}")
    if result.status == "computed":
        print(f"  Measurement:   0x{result.measurement[:48]}...")
        print(f"  {_color('Result:       COMPUTED', _DECISION_COLORS['ALLOW'])}")
        return 0
    print(f"  Status:        blocked ({result.blocker_kind})")
    print(f"  Blocker:       {result.blocker}")
    print(f"  {_color('Result:       BLOCKED — honest finding', _DECISION_COLORS['DENY'])}")
    return 1


def _cmd_freshness(args) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: bundle file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        bundle_dict = json.loads(input_path.read_text())
        bundle = EvidenceBundle.from_dict(bundle_dict)
    except Exception as e:
        print(f"Error: failed to parse bundle: {e}", file=sys.stderr)
        return 1

    current_snapshot = compute_attack_db_snapshot()
    bundle_snapshot = bundle.attack_db_snapshot

    print(f"  Bundle:        {bundle.bundle_id}")
    print(f"  Created:       {bundle.timestamp.isoformat()}")
    print(f"  Expires:       {bundle.expires_at.isoformat()}")
    if bundle_snapshot:
        print(f"  Bundle DB hash: {bundle_snapshot[:16]}…")
        print(f"  Current DB hash: {current_snapshot[:16]}…")

    if bundle_snapshot is None:
        print(
            f"\n  {_color('UNKNOWN', _DECISION_COLORS['DENY'])}: bundle has no attack DB snapshot"
        )
        return 1

    if bundle_snapshot == current_snapshot:
        print(
            f"\n  {_color('FRESH', _DECISION_COLORS['ALLOW'])}: "
            "attack DB unchanged since evaluation"
        )
        if args.verbose:
            _print_attack_count()
        return 0
    else:
        print(
            f"\n  {_color('STALE', _DECISION_COLORS['DENY'])}: "
            "attack DB has changed since evaluation"
        )
        print("    Re-run `confidior verify` to re-evaluate against current data")
        if args.verbose:
            _print_attack_count()
        return 1


def _print_attack_count() -> None:
    try:
        from src.core.attacks import TEE_ATTACKS

        print(f"    Total known attacks: {len(TEE_ATTACKS)}")
    except Exception:
        pass


def _parse_dimension_args(items: list[str]) -> dict[str, str]:
    dims: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid dimension format: {item!r} (expected key=value)")
        key, value = item.split("=", 1)
        dims[key.strip()] = value.strip()
    return dims


def _cmd_verify_badge(args) -> int:
    dimensions: dict[str, str] | None = None
    commitment = args.commitment
    bundle_id = args.bundle_id
    level = args.level
    signature = args.signature

    if getattr(args, "from_fixture", None):
        fixture_dir: Path = args.from_fixture
        if not fixture_dir.is_dir():
            print(f"Error: --from-fixture path is not a directory: {fixture_dir}", file=sys.stderr)
            return 1
        badge_path = fixture_dir / "badge.svg"
        manifest_path = fixture_dir / "manifest.json"
        if not badge_path.exists():
            print(f"Error: missing badge.svg in fixture: {fixture_dir}", file=sys.stderr)
            return 1
        if not manifest_path.exists():
            print(f"Error: missing manifest.json in fixture: {fixture_dir}", file=sys.stderr)
            return 1
        svg = badge_path.read_text()
        attrs = extract_badge_attributes(svg)
        if "commitment" not in attrs:
            print(
                "Error: SVG has no data-commitment attribute; not a Confidior badge?",
                file=sys.stderr,
            )
            return 1
        commitment = str(attrs["commitment"])
        bundle_id = str(attrs.get("bundle_id", ""))
        level_raw = attrs.get("level", 0)
        level = int(level_raw) if isinstance(level_raw, (int, str)) else 0
        dimensions_attr = attrs.get("dimensions")
        dimensions = (
            {k: str(v) for k, v in dimensions_attr.items()}
            if isinstance(dimensions_attr, dict)
            else None
        )
        manifest = json.loads(manifest_path.read_text())
        signature = str(manifest.get("signature", ""))
        if not signature:
            print(
                "Error: manifest.json has no signature field",
                file=sys.stderr,
            )
            return 1
        # Dimensions: prefer manifest's record (matches what was signed)
        # over what's in the SVG (may include cosmetic labels).
        manifest_dims = manifest.get("dimensions")
        if isinstance(manifest_dims, dict):
            dimensions = {k: str(v) for k, v in manifest_dims.items()}
        print(
            f"  Loaded from fixture {fixture_dir}: "
            f"bundle_id={bundle_id}, level={level}, commitment={commitment[:16]}…"
        )
    elif args.badge_svg:
        if not args.badge_svg.exists():
            print(f"Error: badge SVG not found: {args.badge_svg}", file=sys.stderr)
            return 1
        svg = args.badge_svg.read_text()
        attrs = extract_badge_attributes(svg)
        if "commitment" not in attrs:
            print(
                "Error: SVG has no data-commitment attribute; not a Confidior badge?",
                file=sys.stderr,
            )
            return 1
        commitment = str(attrs["commitment"])
        bundle_id = str(attrs.get("bundle_id", ""))
        level_raw = attrs.get("level", 0)
        level = int(level_raw) if isinstance(level_raw, (int, str)) else 0
        dimensions_attr = attrs.get("dimensions")
        dimensions = (
            {k: str(v) for k, v in dimensions_attr.items()}
            if isinstance(dimensions_attr, dict)
            else None
        )
        print(
            f"  Extracted from SVG: bundle_id={bundle_id}, level={level}, commitment={commitment}"
        )
        if not signature:
            print(
                "Error: --signature is required even with --badge-svg "
                "(signature is on the bundle, not the badge)",
                file=sys.stderr,
            )
            return 1
    else:
        if not commitment or not bundle_id or level is None or not signature:
            print(
                "Error: --commitment, --bundle-id, --level, and --signature "
                "are required (or use --badge-svg)",
                file=sys.stderr,
            )
            return 1
        if args.dimension:
            dimensions = _parse_dimension_args(args.dimension)

    if not commitment or not bundle_id or level is None or not signature:
        print("Error: missing commitment, bundle_id, level, or signature", file=sys.stderr)
        return 1

    match = verify_badge(commitment, bundle_id, level, signature, dimensions)
    if match:
        print(
            f"  {_color('MATCH', _DECISION_COLORS['ALLOW'])}: "
            "badge commitment is cryptographically bound to the bundle"
        )
        return 0
    else:
        print(
            f"  {_color('MISMATCH', _DECISION_COLORS['DENY'])}: "
            "badge commitment does not match bundle + signature + dimensions"
        )
        return 1


def _cmd_attacks_map_cve_tcb(args) -> int:
    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"Error: archaeology DB not found: {db_path}", file=sys.stderr)
        return 1

    applied, skipped = map_cve_tcb_for_db(db_path, dry_run=args.dry_run)
    mode = "dry-run" if args.dry_run else "applied"
    print(f"  CVE→TCB mappings {mode}: {len(applied)}")
    for m in applied:
        print(f"    {m.attack_name} ({m.cve_id}) -> {m.platform.value} >= {m.fixed_version}")
    if skipped:
        print(f"  Skipped (existing min_svn): {len(skipped)}")
        for m in skipped:
            print(f"    {m.attack_name} ({m.cve_id}) -> {m.platform.value} >= {m.fixed_version}")
    return 0


def _cmd_attacks_sync_nvd(args, db_path: Path) -> int:
    """NVD-backed sync: fetch high/critical TEE CVEs (free, no credentials) + seed."""
    try:
        from scripts.fetch_tee_cves import (
            _seed_tcb_records,
            fetch_cves_nvd,
            nvd_to_attack_record,
        )
        from src.tools.archaeology import ArchaeologyDB, seed_attacks_from_list
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print("Fetching TEE-relevant CVEs from NVD (free, no credentials)...")
    try:
        cves = fetch_cves_nvd()
    except Exception as e:
        print(f"Error: NVD fetch failed: {e}", file=sys.stderr)
        return 1

    records = [nvd_to_attack_record(c) for c in cves]
    print(f"  Total high/critical TEE-relevant CVEs from NVD: {len(records)}")

    if args.dry_run:
        for r in records[:10]:
            print(f"    {r.cve_id} ({r.year}): {r.impact[:60]}")
        return 0

    db = ArchaeologyDB(db_path=db_path)
    try:
        count = seed_attacks_from_list(db, records)
        print(f"  Inserted {count} new attacks into {db_path}")
        _seed_tcb_records(db, cves)
    finally:
        db.close()
    return 0


def _cmd_attacks_sync(args) -> int:
    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if getattr(args, "source", "opencve") == "nvd":
        return _cmd_attacks_sync_nvd(args, db_path)

    try:
        summary = sync_cves(
            db_path=db_path,
            max_pages=args.max_pages,
            dry_run=args.dry_run,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("  Register at https://app.opencve.io/signup/ for an API token.", file=sys.stderr)
        return 1

    mode = "dry-run" if args.dry_run else "synced"
    print(f"  OpenCVE fetch: {summary['fetched']} unique high/critical CVEs")
    print(f"  New attack_records {mode}: {summary['inserted']}")
    print(f"  CVE→TCB mappings {mode}: {len(summary['tcb_mappings_applied'])}")
    for m in summary["tcb_mappings_applied"]:
        print(f"    {m.attack_name} ({m.cve_id}) -> {m.platform.value} >= {m.fixed_version}")

    if args.bundle_dir:
        bundle_dir = Path(args.bundle_dir)
        affected = find_affected_bundles(db_path, bundle_dir)
        print(f"\n  Bundles checked: {len(list(bundle_dir.glob('*.json')))}")
        print(f"  Bundles flagged for re-evaluation: {len(affected)}")
        for item in affected:
            status = "snapshot-changed" if item["snapshot_changed"] else "attacks-changed"
            print(
                f"    {item['bundle_id']} [{status}] -> {item['attack_count']} unmitigated attacks"
            )

        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "rescore_trigger_report.json"
        with open(report_path, "w") as f:
            json.dump(
                {
                    "fetched": summary["fetched"],
                    "inserted": summary["inserted"],
                    "tcb_mappings_applied": [
                        {
                            "cve_id": m.cve_id,
                            "attack_name": m.attack_name,
                            "platform": m.platform.value,
                            "fixed_version": m.fixed_version,
                        }
                        for m in summary["tcb_mappings_applied"]
                    ],
                    "affected_bundles": affected,
                },
                f,
                indent=2,
            )
        print(f"\n  Report written: {report_path}")

    return 0


def _cmd_verify(args) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(input_path) as f:
        hex_data = f.read()

    platform = args.platform
    if platform is None:
        platform = detect_platform(hex_data)
        print(f"  Detected platform: {platform}")

    parse_fn = _load_adapter(platform)
    node = parse_fn(hex_data)

    if args.verify:
        verify_fn = _load_verify_fn(platform)
        if verify_fn:
            if platform == "sevsnp":
                verify_result = verify_fn(
                    hex_data,
                    product=args.product,
                    vlek_cert=args.vlek_cert,
                )
            else:
                verify_result = verify_fn(hex_data)
            node.metadata["crypto_verification"] = verify_result
            if verify_result.get("valid"):
                print("  Crypto signature: VALID")
            else:
                err = verify_result.get("error", "unknown error")
                print(f"  Crypto signature: FAILED ({err})")
        else:
            print(f"  Crypto verification not available for {platform}")

    graph = EvidenceGraph()
    graph.add_node(node)

    policy = load_policy(str(policy_path))
    policy_eval = evaluate(graph, policy)
    db_path = Path(__file__).resolve().parent.parent.parent / "data" / "archaeology.db"
    if db_path.exists():
        set_archaeology_db_path(db_path)
    assurance = compute_assurance_level(
        graph,
        score_profile=args.score_profile,
        tcb_db_path=str(db_path) if db_path.exists() else None,
        tcb_fmspc=args.fmspc,
        threat_model=ThreatModelTier(args.threat_model),
    )

    # Load or create the operator's persistent key (Present / signed trust model).
    if args.key_path:
        private_key, _public_key, is_new = load_or_create_keypair(args.key_path)
        if is_new:
            print(f"  Created new operator keypair at {args.key_path}")
        else:
            print(f"  Loaded existing operator keypair from {args.key_path}")
    else:
        private_key = None  # signal to create_signed_bundle to generate ephemeral
        print("  Using ephemeral key (pass --key-path to persist; see docs/TRUST-MODEL.md)")

    bundle, _private_key = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload=args.workload,
        private_key=private_key,
        enable_rekor_anchoring=not args.no_rekor,
    )

    c5_mappings = evaluate_c5_compliance(graph)
    bundle.compliance_mappings = c5_mappings

    bundle_path = output_dir / "evidence_bundle.json"
    with open(bundle_path, "w") as f:
        json.dump(bundle.to_dict(), f, indent=2)

    report_path = output_dir / "report.md"
    _write_report(report_path, bundle, node, c5_mappings)

    c5_report_path = output_dir / "c5_report.md"
    c5_report = generate_c5_report(graph, c5_mappings)
    c5_report_path.write_text(c5_report)

    badge_path = output_dir / "badge.svg"
    sig_hex = bundle.signatures[0].signature_hex if bundle.signatures else ""
    _write_badge(badge_path, bundle.assurance, bundle.bundle_id, sig_hex)

    satisfied = sum(1 for m in c5_mappings if m.status.value == "SATISFIED")
    partial = sum(1 for m in c5_mappings if m.status.value == "PARTIAL")
    gap = sum(1 for m in c5_mappings if m.status.value == "GAP")

    rekor_status = None
    if bundle.signatures and bundle.signatures[0].rekor_entry:
        re = bundle.signatures[0].rekor_entry
        rekor_status = f"index={re.log_index} uuid={re.entry_uuid[:12]}…"

    _print_result(
        policy_eval,
        assurance,
        satisfied,
        partial,
        gap,
        report_path,
        c5_report_path,
        bundle_path,
        badge_path,
        rekor_status=rekor_status,
        key_path=args.key_path,
    )

    return 0


_DECISION_COLORS = {"ALLOW": "\033[32m", "DENY": "\033[31m"}
_RISK_COLORS = {
    "LOW": "\033[32m",
    "MEDIUM": "\033[33m",
    "HIGH": "\033[31m",
    "CRITICAL": "\033[31m\033[1m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _color(text: str, color_code: str) -> str:
    return f"{color_code}{text}{_RESET}"


def _print_result(
    policy_eval,
    assurance,
    satisfied,
    partial,
    gap,
    report_path,
    c5_report_path,
    bundle_path,
    badge_path,
    rekor_status=None,
    key_path=None,
) -> None:
    decision_color = _DECISION_COLORS.get(policy_eval.decision.value, "")
    risk_color = _RISK_COLORS.get(assurance.residual_risk.value, "")

    decision_str = _color(policy_eval.decision.value, decision_color)
    risk_str = _color(assurance.residual_risk.value, risk_color)

    print()
    score_str = (
        f"{assurance.score.total}/100 ({assurance.score.grade})" if assurance.score else "n/a"
    )
    subscores = assurance.score.subscores if assurance.score else {}

    print()
    print(f"  {_BOLD}Decision{_RESET}       {decision_str}")
    print(f"  {_BOLD}Assurance{_RESET}      {assurance.label}")
    print(f"  {_BOLD}Risk{_RESET}           {risk_str}")
    print(f"  {_BOLD}Score{_RESET}          {score_str}")
    if subscores:
        print(
            f"  {_DIM}  subscores: "
            + ", ".join(f"{k}={v}" for k, v in subscores.items())
            + f"{_RESET}"
        )
    if assurance.score and assurance.score.platform_score is not None:
        print(
            f"  {_DIM}  split:     platform={assurance.score.platform_score}/100 "
            f"(attack surface), quote={assurance.score.quote_score}/100 "
            f"(this attestation){_RESET}"
        )
    print(f"  {_BOLD}C5{_RESET}             {satisfied} satisfied, {partial} partial, {gap} gap")
    print()
    print(f"  {_DIM}report:   {report_path}{_RESET}")
    print(f"  {_DIM}c5:      {c5_report_path}{_RESET}")
    print(f"  {_DIM}bundle:  {bundle_path}{_RESET}")
    print(f"  {_DIM}badge:   {badge_path}{_RESET}")
    if rekor_status:
        print(f"  {_DIM}rekor:   {rekor_status} (anchored){_RESET}")
    else:
        print(f"  {_DIM}rekor:   (not anchored; pass without --no-rekor to anchor){_RESET}")
    if key_path:
        print(f"  {_DIM}key:     {key_path} (operator-persistent){_RESET}")
    print()
    print(f"  {_DIM}open in browser → confidior-web{_RESET}")
    print()

    return


def _write_report(path: Path, bundle, node, c5_mappings=None) -> None:
    lines = [
        "# Confidior Verification Report",
        "",
        f"**Bundle ID:** {bundle.bundle_id}",
        f"**Timestamp:** {bundle.timestamp.isoformat()}",
        f"**Workload:** {bundle.workload}",
        "",
        "## Policy Evaluation",
        "",
        f"- **Decision:** {bundle.policy_evaluation.decision.value}",
        f"- **Rules passed:** {', '.join(bundle.policy_evaluation.rules_passed) or 'none'}",
        f"- **Rules failed:** {', '.join(bundle.policy_evaluation.rules_failed) or 'none'}",
        "",
        "## Assurance",
        "",
        f"- **Level:** {bundle.assurance.label}",
        f"- **Residual risk:** {bundle.assurance.residual_risk.value}",
        f"- **Score:** {bundle.assurance.score.total}/100 ({bundle.assurance.score.grade})"
        if bundle.assurance.score
        else "- **Score:** n/a",
        f"- **Boundary statement:** {bundle.assurance.boundary_statement}",
        "",
        "## Evidence",
        "",
        f"- **Platform:** {node.platform.value}",
        f"- **Measurement:** {node.measurement[:32]}...",
        f"- **Debug disabled:** {node.debug_disabled}",
        f"- **TCB version:** {node.tcb_version}",
        f"- **TCB status:** {node.tcb_status.value}",
        "",
    ]

    # The grade is shown with its arithmetic so a reader can argue with it
    # rather than trusting it; every value comes from the display model.
    detail = report_items(bundle.assurance)
    if detail:
        lines += ["## Grading", ""]
        lines += [f"- **{item.label}:** {item.value}" for item in detail]
        lines.append("")

    explain = explain_lines(bundle.assurance)
    if explain:
        lines += ["## How this number was produced", ""]
        lines += list(explain)
        lines.append("")

    if c5_mappings:
        lines.append("## C5:2026 Compliance Summary")
        lines.append("")
        satisfied = sum(1 for m in c5_mappings if m.status.value == "SATISFIED")
        partial = sum(1 for m in c5_mappings if m.status.value == "PARTIAL")
        gap = sum(1 for m in c5_mappings if m.status.value == "GAP")
        lines.append(f"- **SATISFIED:** {satisfied}")
        lines.append(f"- **PARTIAL:** {partial}")
        lines.append(f"- **GAP:** {gap}")
        lines.append("")

        cc_mappings = [
            m
            for m in c5_mappings
            if m.control_id.startswith("OPS-32") or m.control_id.startswith("OPS-33")
        ]
        if cc_mappings:
            lines.append("### Confidential Computing Controls")
            lines.append("")
            for m in cc_mappings:
                lines.append(f"- **{m.control_id}**: {m.status.value}")
                if m.gap_description:
                    lines.append(f"  - Gap: {m.gap_description}")
            lines.append("")

    path.write_text("\n".join(lines))


def _write_badge(path: Path, assurance, bundle_id: str = "", signature_hex: str = "") -> None:
    # The score-derived items come from the display model so every surface
    # reports the same values.
    dims = dict(assurance.dimensions)
    dims.update(badge_dims(assurance))
    path.write_text(generate_badge_svg(assurance, bundle_id, signature_hex, dimensions=dims))


if __name__ == "__main__":
    import sys

    sys.exit(main())
