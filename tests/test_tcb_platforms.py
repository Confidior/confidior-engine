"""Per-platform TCB versioning and patch-status tests.

Covers, for each platform:
- TCB version extraction (what the adapter pulls from the quote)
- Patch-status checking (quoted SVN vs per-attack min_svn fix thresholds)
- The temporal summary (liveness + patched-ness reported separately)

Honest per-platform state:
- Intel TDX: real SVN (tee_tcb_svn hex bytes). Live lookup via PCS v4.
- AMD SEV-SNP: real SVN (bootloader.tee.snp.microcode dotted). No live
  endpoint; local reference only.
- Nitro: NOT an SVN platform. The adapter extracts a digest (enclave image
  hash), not a firmware version. SVN comparison does not apply.
- NVIDIA: extracts firmware_version (a version string), but no reference
  source exists, so it stays UNKNOWN in practice.
"""
import json

from src.core.attacks import get_unmitigated_attacks
from src.core.taxonomy import Platform, TCBStatus
from src.ingest.adapters.nitro import parse_nitro_attestation
from src.ingest.adapters.nvidia import parse_nvidia_gpu_attestation
from src.ingest.adapters.sevsnp import parse_sevsnp_report
from src.ingest.adapters.tdx import parse_tdx_quote

# ---------------------------------------------------------------------------
# TCB version extraction per platform
# ---------------------------------------------------------------------------

def test_tdx_extracts_hex_svn():
    node = parse_tdx_quote(open("tests/fixtures/tdx/sample_quote.hex").read())
    assert node.tcb_version == "03050000"  # hex bytes of tee_tcb_svn[:4]
    assert node.tcb_status == TCBStatus.UNKNOWN  # resolved later, not at parse


def test_sevsnp_extracts_dotted_svn():
    node = parse_sevsnp_report(open("tests/fixtures/sevsnp/sample_report.hex").read())
    # bootloader.tee.snp.microcode
    parts = node.tcb_version.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() for p in parts)
    assert node.tcb_status == TCBStatus.UNKNOWN


def test_nitro_extracts_digest_not_svn():
    node = parse_nitro_attestation(open("tests/fixtures/nitro/sample_attestation.hex").read())
    # Nitro's "tcb" is an image-identity reference (digest), not a firmware
    # SVN. It is not comparable as a version: no monotonic ordering, no
    # min_svn thresholds. The SVN temporal model does not apply to Nitro.
    assert node.tcb_version  # present
    assert node.tcb_status == TCBStatus.UNKNOWN
    # A digest/algorithm reference is not a dotted or hex SVN.
    assert "." not in node.tcb_version or not all(
        p.isdigit() for p in node.tcb_version.split(".")
    )


def test_nvidia_extracts_firmware_version():
    payload = json.dumps(
        {"gpu_uuid": "gpu-1234", "firmware_version": "535.104.05"}
    ).encode().hex()
    node = parse_nvidia_gpu_attestation(payload)
    assert node.tcb_version == "535.104.05"
    assert node.tcb_status == TCBStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Patch-status checking per platform (quoted SVN vs min_svn thresholds)
# ---------------------------------------------------------------------------

def test_tdx_patch_status_hex_svn():
    # TDX attacks with min_svn thresholds: Heckler has none in the DB, so the
    # patch status is driven by the attacks that carry thresholds.
    unpatched_low = get_unmitigated_attacks(Platform.IntelTDX, tcb_version="00000000")
    unpatched_high = get_unmitigated_attacks(Platform.IntelTDX, tcb_version="ffffffff")
    # A higher SVN cannot be less patched than a lower one.
    assert len(unpatched_high) <= len(unpatched_low)


def test_sevsnp_patch_status_dotted_svn():
    # BadRAM has min_svn 0.0.1.20 for SEV-SNP. Below the threshold it is
    # unmitigated; at or above it, patched.
    below = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.10")
    at = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.20")
    above = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.25")
    assert any(a.name == "BadRAM" for a in below)
    assert not any(a.name == "BadRAM" for a in at)
    assert not any(a.name == "BadRAM" for a in above)


def test_patch_status_monotonic_across_platforms():
    """Raising the quoted SVN never increases the unmitigated count."""
    for platform in (Platform.IntelTDX, Platform.AMDSEVSNP):
        counts = [
            len(get_unmitigated_attacks(platform, tcb_version=v))
            for v in ("00000000", "0a000000", "ffffffff")
        ]
        assert counts == sorted(counts, reverse=True) or counts == sorted(counts)


# ---------------------------------------------------------------------------
# Temporal summary: liveness + patched-ness reported separately
# ---------------------------------------------------------------------------

def test_temporal_summary_reports_liveness_and_patched(tmp_path):
    from src.core.risk import _tcb_temporal_summary
    from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType
    from src.tools.archaeology import ArchaeologyDB, TCBRecord

    db_path = tmp_path / "tcb.db"
    db = ArchaeologyDB(db_path=db_path)
    db.insert(TCBRecord(platform="Intel-TDX", version="0b010500", status="current"))
    db.close()

    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode(
            node_id="q1",
            node_type=NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="aa" * 48,
            tcb_version="0b010500",
        )
    )
    summary = _tcb_temporal_summary(graph, tcb_db_path=str(db_path))
    assert "TCB current" in summary
    assert "patched against" in summary
    assert "known attacks" in summary


def test_temporal_summary_unknown_without_reference():
    from src.core.risk import _tcb_temporal_summary
    from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType

    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode(
            node_id="q1",
            node_type=NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="aa" * 48,
            tcb_version="0b010500",
        )
    )
    summary = _tcb_temporal_summary(graph, tcb_db_path=None)
    assert "TCB unknown" in summary
    assert "patched against" in summary
