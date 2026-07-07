from __future__ import annotations

from tdx_pytools import Quote, TcbStatus

from src.core.taxonomy import (
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)


def parse_tdx_quote(hex_data: str) -> EvidenceNode:
    raw_bytes = bytes.fromhex(hex_data.strip())
    quote = Quote.unpack(raw_bytes)

    tcb_status_map = {
        TcbStatus.UP_TO_DATE: TCBStatus.CURRENT,
        TcbStatus.OUT_OF_DATE: TCBStatus.EXPIRED,
        TcbStatus.REVOKED: TCBStatus.REVOKED,
    }

    td_attr = quote.body.td_attributes
    debug_disabled = (td_attr[0] & 0x01) == 0

    tcb_version = quote.body.tee_tcb_svn[:4].hex()

    return EvidenceNode(
        node_id=f"tdx-quote-{quote.body.mr_td[:8].hex()}",
        node_type=NodeType.QUOTE,
        platform=Platform.IntelTDX,
        measurement=quote.body.mr_td.hex(),
        debug_disabled=debug_disabled,
        tcb_version=tcb_version,
        tcb_status=TCBStatus.UNKNOWN,
        firmware_version=tcb_version,
        metadata={
            "version": quote.header.version,
            "mr_seam": quote.body.mr_seam.hex(),
            "rtmr0": quote.body.rtmr0.hex(),
            "rtmr1": quote.body.rtmr1.hex(),
            "rtmr2": quote.body.rtmr2.hex(),
            "rtmr3": quote.body.rtmr3.hex(),
        },
    )


def verify_tdx_quote(hex_data: str) -> dict:
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
