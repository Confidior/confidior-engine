"""Intel TDX attestation quote parser and verifier."""

from __future__ import annotations

from tdx_pytools import Quote

from src.core.taxonomy import (
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)


def parse_tdx_quote(hex_data: str) -> EvidenceNode:
    """Parse a hex-encoded TDX quote into an EvidenceNode."""
    raw_bytes = bytes.fromhex(hex_data.strip())
    quote = Quote.unpack(raw_bytes)

    td_attr = quote.body.td_attributes
    debug_disabled = (td_attr[0] & 0x01) == 0

    tcb_version = quote.body.tee_tcb_svn[:4].hex()

    # report_data is the only field a relying party controls: the platform copies
    # in whatever the challenger supplied, which is how a quote is bound to a
    # session. It was previously parsed and discarded, so no quote could ever be
    # tied to the challenge it answered. Stored hex-encoded and trimmed of
    # trailing zeros, since that is how a nonce or digest is placed in the
    # 64-byte field and the padding is not part of the claim.
    report_data = quote.body.report_data.rstrip(b"\x00").hex()

    return EvidenceNode(
        node_id=f"tdx-quote-{quote.body.mr_td[:8].hex()}",
        node_type=NodeType.QUOTE,
        platform=Platform.IntelTDX,
        measurement=quote.body.mr_td.hex(),
        debug_disabled=debug_disabled,
        tcb_version=tcb_version,
        tcb_status=TCBStatus.UNKNOWN,
        tcb_level=f"tdx:{tcb_version}",
        tcb_reference_id=f"version={quote.header.version}",
        firmware_version=tcb_version,
        metadata={
            "version": quote.header.version,
            "report_data": report_data,
            # A non-empty report_data is the challenge the quote answered. That
            # is the same material BOUND_TO compares across platforms, so it is
            # published under the shared key rather than left in a private field
            # where cross-platform corroboration could not see it.
            **({"binding": report_data} if report_data else {}),
            "mr_seam": quote.body.mr_seam.hex(),
            "rtmr0": quote.body.rtmr0.hex(),
            "rtmr1": quote.body.rtmr1.hex(),
            "rtmr2": quote.body.rtmr2.hex(),
            "rtmr3": quote.body.rtmr3.hex(),
        },
    )


def verify_tdx_quote(hex_data: str) -> dict:
    """Verify a TDX quote's signature via the TDX Quote Verification Library."""
    """Verify a TDX quote's ECDSA-P256 signature against Intel's PCK certificate chain.
    
    Uses cvm-attest to parse the quote, fetch the Intel root CA, and verify the signature chain.
    
    Returns dict with 'valid' (bool) and 'error' (str or None).
    """
    try:
        from cvm_attest.models import AttestationEvidence, AttestStatus, TeeType
        from cvm_attest.tdx.verify import verify_evidence

        raw_bytes = bytes.fromhex(hex_data.strip())
        evidence = AttestationEvidence(
            tee_type=TeeType.TDX,
            raw_quote=raw_bytes,
            report_data=raw_bytes,
            certificates=[],
            aux_data={},
        )
        result = verify_evidence(evidence, fetch_root_ca=True)
        return {
            "valid": result.status == AttestStatus.PASS,
            "error": None if result.status == AttestStatus.PASS else "; ".join(result.errors or []),
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}
