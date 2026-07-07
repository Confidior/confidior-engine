from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.core.attacks import compute_attack_db_snapshot
from src.core.policy import evaluate, load_policy
from src.core.risk import compute_assurance_level, set_archaeology_db_path
from src.core.taxonomy import EvidenceBundle, EvidenceGraph
from src.export.badge import generate_badge_svg
from src.export.c5 import evaluate_c5_compliance, generate_c5_report
from src.export.dsse import (
    create_signed_bundle,
    load_or_create_keypair,
)
from src.export.measurement import (
    load_registry,
    verify_measurement,
)

ADAPTERS = {
    "tdx": ("src.ingest.adapters.tdx", "parse_tdx_quote", "verify_tdx_quote"),
    "sevsnp": ("src.ingest.adapters.sevsnp", "parse_sevsnp_report", "verify_sevsnp_report"),
    "nitro": ("src.ingest.adapters.nitro", "parse_nitro_attestation", "verify_nitro_attestation"),
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
    raise ValueError(
        "Could not detect platform. Try --platform tdx|sevsnp|nitro"
    )


def main(argv: list[str] | None = None) -> int:
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

    measure = sub.add_parser("measure", help="Compare attestation measurement against expected value")
    measure.add_argument("--input", required=True, help="Path to raw attestation data (hex file)")
    measure.add_argument("--platform", required=True, choices=list(ADAPTERS.keys()), help="TEE platform")
    measure.add_argument("--workload", required=True, help="Workload identifier (must exist in registry)")
    measure.add_argument("--registry", required=True, help="Path to measurement registry YAML file")

    freshness = sub.add_parser("freshness", help="Check whether an evidence bundle's attack DB snapshot is current")
    freshness.add_argument("--input", required=True, help="Path to evidence_bundle.json")
    freshness.add_argument("--verbose", action="store_true", help="Show attack count details")

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

    return 0


def _print_measure_result(result) -> None:
    print(f"  Workload:      {result.workload}")
    print(f"  Platform:      {result.platform}")
    print(f"  Actual:        0x{result.actual_measurement[:48]}...")
    print(f"  Expected:      0x{result.expected_measurement[:48]}...")
    if result.source:
        print(f"  Source:        {result.source} ({result.source_url})" if result.source_url else f"  Source:        {result.source}")
    if result.error:
        print(f"  Error:         {result.error}")
        print(f"  {_color('Result:       MISMATCH', _DECISION_COLORS['DENY'])}")
    elif result.match:
        print(f"  {_color('Result:       MATCH', _DECISION_COLORS['ALLOW'])}")
    else:
        print(f"  {_color('Result:       MISMATCH', _DECISION_COLORS['DENY'])}")


def _cmd_measure(args) -> int:
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
    return 0 if result.match else 1


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
        print(f"\n  {_color('UNKNOWN', _DECISION_COLORS['DENY'])}: bundle has no attack DB snapshot")
        return 1

    if bundle_snapshot == current_snapshot:
        print(f"\n  {_color('FRESH', _DECISION_COLORS['ALLOW'])}: attack DB unchanged since evaluation")
        if args.verbose:
            _print_attack_count()
        return 0
    else:
        print(f"\n  {_color('STALE', _DECISION_COLORS['DENY'])}: attack DB has changed since evaluation")
        print(f"    Re-run `confidior verify` to re-evaluate against current data")
        if args.verbose:
            _print_attack_count()
        return 1


def _print_attack_count() -> None:
    try:
        from src.core.attacks import TEE_ATTACKS
        print(f"    Total known attacks: {len(TEE_ATTACKS)}")
    except Exception:
        pass


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
                    hex_data, product=args.product, vlek_cert=args.vlek_cert,
                )
            else:
                verify_result = verify_fn(hex_data)
            node.metadata["crypto_verification"] = verify_result
            if verify_result.get("valid"):
                print(f"  Crypto signature: VALID")
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
    assurance = compute_assurance_level(graph)

    # Load or create the operator's persistent key (Phase 0.5 trust model).
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

    _print_result(policy_eval, assurance, satisfied, partial, gap,
                  report_path, c5_report_path, bundle_path, badge_path,
                  rekor_status=rekor_status, key_path=args.key_path)

    return 0


_DECISION_COLORS = {"ALLOW": "\033[32m", "DENY": "\033[31m"}
_RISK_COLORS = {
    "LOW": "\033[32m", "MEDIUM": "\033[33m",
    "HIGH": "\033[31m", "CRITICAL": "\033[31m\033[1m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _color(text: str, color_code: str) -> str:
    return f"{color_code}{text}{_RESET}"


def _print_result(policy_eval, assurance, satisfied, partial, gap,
                  report_path, c5_report_path, bundle_path, badge_path,
                  rekor_status=None, key_path=None) -> None:
    decision_color = _DECISION_COLORS.get(policy_eval.decision.value, "")
    risk_color = _RISK_COLORS.get(assurance.residual_risk.value, "")

    decision_str = _color(policy_eval.decision.value, decision_color)
    risk_str = _color(assurance.residual_risk.value, risk_color)

    print()
    print(f"  {_BOLD}Decision{_RESET}       {decision_str}")
    print(f"  {_BOLD}Assurance{_RESET}      {assurance.label}")
    print(f"  {_BOLD}Risk{_RESET}           {risk_str}")
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

    return 0


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

        cc_mappings = [m for m in c5_mappings if m.control_id.startswith("OPS-32") or m.control_id.startswith("OPS-33")]
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
    path.write_text(generate_badge_svg(assurance, bundle_id, signature_hex))
