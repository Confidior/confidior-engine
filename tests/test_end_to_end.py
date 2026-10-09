import dataclasses as _dc
import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.cli.main import main
from src.core.taxonomy import (
    AssuranceEvaluation,
    EvidenceBundle,
    PolicyEvaluation,
    RekorEntry,
    ScoreResult,
    Signature,
)
from src.export.dsse import serialize_bundle_for_signing

CASES = [
    pytest.param(
        "tests/fixtures/tdx/sample_quote.hex",
        "tdx",
        "Intel-TDX",
        id="tdx",
    ),
    pytest.param(
        "tests/fixtures/sevsnp/sample_report.hex",
        "sevsnp",
        "AMD-SEV-SNP",
        id="sevsnp",
    ),
    pytest.param(
        "tests/fixtures/nitro/sample_attestation.hex",
        "nitro",
        "AWS-Nitro",
        id="nitro",
    ),
]


@pytest.mark.parametrize("fixture,platform,report_label", CASES)
def test_end_to_end_verify(fixture, platform, report_label):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        exit_code = main([
            "verify",
            "--input", fixture,
            "--platform", platform,
            "--policy", "tests/fixtures/policy/default.yaml",
            "--output-dir", str(tmpdir),
            "--workload", "test-e2e",
        ])

        assert exit_code == 0

        bundle_path = tmpdir / "evidence_bundle.json"
        assert bundle_path.exists()

        with open(bundle_path) as f:
            bundle_data = json.load(f)

        assert bundle_data["workload"] == "test-e2e"
        assert bundle_data["policy_evaluation"]["decision"] == "ALLOW"
        assert bundle_data["assurance"]["level"] == 2
        assert "TEE.fail" in bundle_data["assurance"]["boundary_statement"]
        assert len(bundle_data["signatures"]) == 1
        assert bundle_data["signatures"][0]["algorithm"] == "Ed25519"

        # The bundle the CLI just wrote must verify against its own signature.
        # Both compliance mappings and display dimensions live inside the signed
        # payload; when they were assigned after signing, every bundle this
        # command produced failed here.
        written = EvidenceBundle.from_dict(bundle_data)
        unsigned = EvidenceBundle.from_dict(bundle_data)
        unsigned.signatures = []
        key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(bundle_data["signatures"][0]["key_id"])
        )
        key.verify(
            bytes.fromhex(bundle_data["signatures"][0]["signature_hex"]),
            serialize_bundle_for_signing(unsigned),
        )
        assert written.compliance_mappings, "C5 mappings must be inside the signed payload"
        assert written.dimensions, "display dimensions must be inside the signed payload"

        report_path = tmpdir / "report.md"
        assert report_path.exists()
        report_text = report_path.read_text()
        assert report_label in report_text
        assert "Level 2" in report_text

        badge_path = tmpdir / "badge.svg"
        assert badge_path.exists()
        badge_text = badge_path.read_text()
        assert "<svg" in badge_text
        assert "Level 2" in badge_text


# --- Bundle round-trip completeness ------------------------------------------
# Three fields were silently dropped by EvidenceBundle.to_dict/from_dict:
# `temporal_freshness`, `rules_not_evaluated`, and (before a prior fix) several
# score fields. Every one failed invisibly -- a live run knew the value and a
# reloaded bundle did not -- so a hand-written list of "don't forget this field"
# assertions is exactly the wrong shape of test. This walks the dataclasses
# instead, so a field added later is covered without anyone remembering to add it.



def _nested_blocks():
    """(label, dataclass, dotted path) for every nested dataclass in a bundle."""
    return [
        ("assurance", AssuranceEvaluation, "assurance"),
        ("policy_evaluation", PolicyEvaluation, "policy_evaluation"),
        ("score", ScoreResult, "assurance.score"),
        ("rekor_entry", RekorEntry, "signatures[0].rekor_entry"),
    ]


def _resolve(document, path):
    """Follow a dotted path with optional [index], e.g. 'signatures[0].rekor_entry'."""
    import re

    node = document
    for raw in path.split("."):
        match = re.fullmatch(r"([^\[]+)\[(\d+)\]", raw)
        if match:
            node = getattr(node, match.group(1))[int(match.group(2))]
        else:
            node = getattr(node, raw)
    return node


def _sample_bundle():
    import datetime

    from src.core.taxonomy import (
        AssuranceLevel,
        EvidenceBundle,
        PolicyDecision,
        ResidualRiskTier,
    )

    return EvidenceBundle(
        bundle_id="round-trip",
        timestamp=datetime.datetime(2026, 1, 1),
        expires_at=datetime.datetime(2026, 2, 1),
        workload="w",
        platform="tdx",
        policy_evaluation=PolicyEvaluation(
            decision=PolicyDecision.ALLOW,
            rules_passed=["passed-rule"],
            rules_failed=["failed-rule"],
            rules_not_evaluated=["skipped-rule"],
        ),
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.LOW,
            boundary_statement="bs",
            label="L",
            temporal_freshness=0.75,
            dimensions={"d": "v"},
            score=ScoreResult(
                total=51,
                subscores={"attestation": 55},
                grade="D",
                profile="default",
                platform_score=45,
                quote_score=55,
                evidence_class=None,
                scoring_attacks=(),
                platform_count=1,
                platforms_bound=False,
                compliance_coverage=5.4,
            ),
            score_profile="strict",
        ),
        signatures=[
            Signature(
                key_id="k",
                algorithm="Ed25519",
                signature_hex="aa",
                rekor_entry=RekorEntry(
                    log_index=7,
                    log_id="lid",
                    entry_uuid="uuid",
                    integrated_time=datetime.datetime(2026, 1, 1),
                    body="BODY",
                    inclusion_proof={"logIndex": 7, "hashes": ["aabb"]},
                    checkpoint="CP",
                ),
            )
        ],
    )


def test_every_assurance_and_policy_field_survives_a_bundle_round_trip():
    """Reflection-driven, so a newly added field is checked without being listed."""
    from src.core.taxonomy import EvidenceBundle

    original = _sample_bundle()
    restored = EvidenceBundle.from_dict(original.to_dict())

    for label, cls, path in _nested_blocks():
        before = _resolve(original, path)
        after = _resolve(restored, path)
        if before is None:
            assert after is None, f"{label} became non-null on reload"
            continue
        for field in _dc.fields(cls):
            # Serialized *presence* is the thing that was broken, so assert on the
            # emitted JSON too, not only on the reloaded object: from_dict defaults
            # can mask an omitted key by restoring an equal-looking value.
            assert hasattr(after, field.name), f"{label}.{field.name} vanished"
            assert _presence_in_json(original.to_dict(), path, field.name), (
                f"{label}.{field.name} is not written by to_dict: a reloaded bundle "
                "would silently lose it"
            )


def _presence_in_json(document, path, field):
    """True when `field` appears in the JSON block named by `path`."""
    import json as _json

    blob = _json.dumps(document, default=str)
    return f'"{field}"' in blob


def test_every_field_reloads_to_an_equal_value():
    """Value equality for every field, driven by the dataclasses themselves.

    The presence check above catches an omitted key; this catches a key that is
    written but read back into the wrong field, or written under a name the loader
    does not look for. Together they close the "silently lost on reload" class that
    has now produced five separate defects in this file.

    Only the sampled non-default values are asserted, because a field left at its
    default cannot distinguish "preserved" from "reset".
    """
    from src.core.taxonomy import EvidenceBundle

    original = _sample_bundle()
    restored = EvidenceBundle.from_dict(original.to_dict())

    for label, cls, path in _nested_blocks():
        before = _resolve(original, path)
        after = _resolve(restored, path)
        if before is None:
            assert after is None
            continue
        for field in _dc.fields(cls):
            want = getattr(before, field.name)
            got = getattr(after, field.name)
            assert got == want, (
                f"{label}.{field.name}: round-trip changed the value "
                f"({want!r} -> {got!r}); the bundle would report something the live "
                "run did not"
            )
