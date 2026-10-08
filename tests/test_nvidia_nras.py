"""NRAS GPU attestation: request shaping and claim-vector reading.

The fixtures are real, not synthetic:
  - nvidia_hopper_sample.json: NVIDIA's own published sample GPU evidence from
    the attestation-sdk repo, common-test-data/serialized_test_evidence/
    hopper_evidence.json (Apache-2.0). arch = HOPPER, which is the arch RedPill
    declares in its nvidia_payload.
  - nras_recorded_response.json: a real HTTP 200 response captured from
    https://nras.attestation.nvidia.com/v4/attest/gpu after reshaping that
    sample. Recorded 2026-10-09.

Everything here runs offline.
"""
import json
from pathlib import Path

import pytest

from src.ingest.adapters.nvidia import (
    build_nras_request,
    decode_nras_jwt_payload,
    read_nras_claims,
    verify_nvidia_gpu_attestation,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nvidia"
HOPPER = FIXTURES / "nvidia_hopper_sample.json"
RECORDED = FIXTURES / "nras_recorded_response.json"
SYNTHETIC = FIXTURES / "sample_gpu.json.hex"


def _hopper_sample():
    return json.loads(HOPPER.read_text())[0]


# --- the fixture itself -----------------------------------------------------


def test_hopper_fixture_is_real_and_correctly_shaped():
    """Guards against someone replacing real evidence with a stub."""
    sample = _hopper_sample()
    assert sample["arch"] == "HOPPER"
    assert sample["evidence"] and sample["certificate"]
    assert len(sample["nonce"]) == 64


def test_synthetic_fixture_does_not_verify():
    """The fabricated fixture must keep failing. It is here to prove the
    adapter refuses input, not to prove it accepts it."""
    result = verify_nvidia_gpu_attestation(SYNTHETIC.read_text())
    assert result["valid"] is False


# --- request shaping --------------------------------------------------------


def test_sdk_sample_is_not_a_valid_nras_request_body():
    """NRAS wants {nonce, arch, evidence_list:[{evidence,certificate}]}. The SDK
    sample has evidence and certificate at the top level, so posting it verbatim
    is a schema error that looks like a bad GPU."""
    sample = _hopper_sample()
    assert "evidence_list" not in sample
    assert "evidence" in sample and "certificate" in sample


def test_build_nras_request_reshapes_into_v4_body():
    req = build_nras_request(_hopper_sample())
    assert set(req) == {"nonce", "arch", "evidence_list"}
    assert req["arch"] == "HOPPER"
    assert len(req["evidence_list"]) == 1
    assert set(req["evidence_list"][0]) == {"evidence", "certificate"}


def test_build_nras_request_honours_a_caller_supplied_nonce():
    """NRAS binds its verdict to the nonce, so a verifier wants its own."""
    req = build_nras_request(_hopper_sample(), nonce="ab" * 32)
    assert req["nonce"] == "ab" * 32


def test_build_nras_request_rejects_incomplete_evidence():
    with pytest.raises(ValueError):
        build_nras_request({"arch": "HOPPER"})
    with pytest.raises(ValueError):
        build_nras_request({"certificate": "x", "evidence": "y"})


# --- reading the verdict ----------------------------------------------------


def test_recorded_response_has_no_failures_only_unverifiable_claims():
    """The whole point of this module.

    NRAS returns x-nvidia-overall-att-result: false for this real Hopper
    sample. The GPU's own attestation report verified completely. The negative
    verdict is driven by driver/VBIOS RIM collateral that was never fetched,
    leaving claims unverifiable. Reporting this as 'GPU attestation failed'
    would be wrong.
    """
    resp = json.loads(RECORDED.read_text())
    payload = decode_nras_jwt_payload(resp[1]["GPU-0"])
    summary = read_nras_claims(payload)

    assert summary["failed_count"] == 0, summary["failed"]
    assert summary["verified_count"] > 0
    assert summary["unverifiable_count"] > 0
    # Negative overall verdict, but not because anything failed.
    assert summary["summary"] == "unverifiable"


def test_hardware_identity_is_readable_from_a_negative_verdict():
    resp = json.loads(RECORDED.read_text())
    payload = decode_nras_jwt_payload(resp[1]["GPU-0"])
    assert payload["hwmodel"] == "GH100"
    assert payload["x-nvidia-gpu-attestation-report-signature-verified"] is True


def test_availability_false_is_not_counted_as_a_failure():
    """NRAS uses False both for 'checked and disagreed' and for 'never
    fetched'. Only the first is a failure."""
    payload = {
        "x-nvidia-overall-att-result": False,
        "x-nvidia-gpu-arch-check": True,
        "x-nvidia-gpu-driver-rim-fetched": False,      # availability
        "x-nvidia-gpu-driver-rim-version-match": None,  # never compared
    }
    summary = read_nras_claims(payload)
    assert summary["failed"] == []
    assert summary["verified"] == ["x-nvidia-gpu-arch-check"]
    assert summary["summary"] == "unverifiable"


def test_a_real_comparison_failure_is_reported_as_failed():
    payload = {
        "x-nvidia-overall-att-result": False,
        "x-nvidia-gpu-arch-check": False,
    }
    summary = read_nras_claims(payload)
    assert summary["failed"] == ["x-nvidia-gpu-arch-check"]
    assert summary["summary"] == "failed"


def test_affirmative_verdict_reads_as_verified():
    summary = read_nras_claims(
        {"x-nvidia-overall-att-result": True, "x-nvidia-gpu-arch-check": True}
    )
    assert summary["summary"] == "verified"


def test_jwt_payload_decode_rejects_non_jwt():
    with pytest.raises(ValueError):
        decode_nras_jwt_payload("not-a-jwt")


# --- live test, opt-in only -------------------------------------------------


@pytest.mark.skipif(
    not __import__("os").environ.get("CONFIDIOR_LIVE_NVIDIA_TEST"),
    reason="live NRAS call; set CONFIDIOR_LIVE_NVIDIA_TEST=1 to run",
)
def test_live_nras_accepts_the_real_hopper_sample():
    """Submits real NVIDIA evidence to the live NRAS endpoint.

    Asserts only that NRAS responded with a well-formed verdict. It does NOT
    force a pass: a rejection is a legitimate outcome and this test must never
    be weakened to manufacture one.
    """
    import urllib.request

    from src.ingest.adapters.nvidia import NRAS_ENDPOINT

    req_body = build_nras_request(_hopper_sample())
    request = urllib.request.Request(
        NRAS_ENDPOINT,
        data=json.dumps(req_body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as resp:
        assert resp.status == 200
        payload = json.loads(resp.read().decode())
    summary = read_nras_claims(decode_nras_jwt_payload(payload[1]["GPU-0"]))
    assert summary["overall_result"] in (True, False)
