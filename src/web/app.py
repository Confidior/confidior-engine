from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Request, UploadFile, Form, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.core.taxonomy import (
    EvidenceBundle, EvidenceGraph, ComplianceStatus,
)
from src.core.risk import compute_assurance_level, set_archaeology_db_path
from src.core.policy import load_policy, evaluate
from src.ingest.adapters.tdx import parse_tdx_quote
from src.ingest.adapters.sevsnp import parse_sevsnp_report
from src.ingest.adapters.nitro import parse_nitro_attestation
from src.export.dsse import create_signed_bundle, serialize_bundle_for_signing
from src.export.badge import generate_badge_svg
from src.export.c5 import evaluate_c5_compliance, generate_c5_report
from src.tools.archaeology import ArchaeologyDB

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Confidior", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.cache = None


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        accept = request.headers.get("accept", "")
        wants_json = "application/json" in accept and "text/html" not in accept
        if not wants_json:
            return templates.TemplateResponse(request, "404.html", {
                "request": request,
                "path": request.url.path,
            }, status_code=404)
    return HTMLResponse(
        content=f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
        status_code=exc.status_code,
    )

ARCHAEOLOGY_DB_PATH = BASE_DIR / "data" / "archaeology.db"
set_archaeology_db_path(ARCHAEOLOGY_DB_PATH)

evaluations: list[dict] = []

ADAPTERS = {
    "tdx": parse_tdx_quote,
    "sevsnp": parse_sevsnp_report,
    "nitro": parse_nitro_attestation,
}

_CATEGORY_LABELS = {
    "memory_bus_interposition": "Memory Bus",
    "rogue_memory_module": "Rogue Memory",
    "performance_counter_side_channel": "Perf Counter",
    "chosen_plaintext_attack": "Chosen Plaintext",
    "interrupt_signal_ahoi": "Interrupt/Signal",
    "cache_side_channel": "Cache",
    "speculative_execution": "Speculative",
    "memory_corruption": "Memory Corruption",
    "architectural": "Architectural",
    "rowhammer": "Rowhammer",
    "voltage_manipulation": "Voltage",
    "synchronization_bug": "Sync Bug",
}

_LEVEL_COLORS = {
    0: "#6b7280", 1: "#f59e0b", 2: "#f97316",
    3: "#3b82f6", 4: "#10b981", 5: "#6366f1",
}
_RISK_COLORS = {
    "LOW": "#10b981", "MEDIUM": "#f59e0b",
    "HIGH": "#f97316", "CRITICAL": "#ef4444",
}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "request": request,
        "evaluations": evaluations[:10],
    })


@app.get("/submit", response_class=HTMLResponse)
async def submit_page(request: Request):
    return templates.TemplateResponse(request, "submit.html", {
        "request": request,
        "platforms": list(ADAPTERS.keys()),
    })


@app.post("/submit", response_class=HTMLResponse)
async def run_submit(
    request: Request,
    platform: str = Form(...),
    quote_data: str = Form(default=""),
    quote_file: UploadFile = File(default=None),
    workload: str = Form(default="unknown"),
):
    quote_hex = quote_data.strip()
    if quote_file and quote_file.filename:
        content = await quote_file.read()
        quote_hex = content.decode().strip()

    if not quote_hex:
        return templates.TemplateResponse(request, "submit.html", {
            "request": request,
            "platforms": list(ADAPTERS.keys()),
            "error": "No quote data provided. Paste hex or upload a file.",
        })

    parse_fn = ADAPTERS.get(platform)
    if not parse_fn:
        return templates.TemplateResponse(request, "submit.html", {
            "request": request,
            "platforms": list(ADAPTERS.keys()),
            "error": f"Unknown platform: {platform}",
        })

    try:
        node = parse_fn(quote_hex)
    except Exception as e:
        return templates.TemplateResponse(request, "submit.html", {
            "request": request,
            "platforms": list(ADAPTERS.keys()),
            "error": f"Failed to parse quote: {e}",
        })

    graph = EvidenceGraph()
    graph.add_node(node)

    policy_path = BASE_DIR / "tests" / "fixtures" / "policy" / "default.yaml"
    policy_eval = None
    if policy_path.exists():
        policy = load_policy(str(policy_path))
        policy_eval = evaluate(graph, policy)

    assurance = compute_assurance_level(graph)
    c5_mappings = evaluate_c5_compliance(graph)

    bundle, private_key = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload=workload,
    )
    bundle.compliance_mappings = c5_mappings

    sig_hex = bundle.signatures[0].signature_hex if bundle.signatures else ""
    badge_svg = generate_badge_svg(assurance, bundle.bundle_id, sig_hex)
    badge_path = STATIC_DIR / f"badge-{bundle.bundle_id}.svg"
    badge_path.write_text(badge_svg)

    c5_report = generate_c5_report(graph, c5_mappings)
    c5_report_path = STATIC_DIR / f"c5-{bundle.bundle_id}.md"
    c5_report_path.write_text(c5_report)

    bundle_json = json.dumps(bundle.to_dict(), indent=2)
    bundle_path = STATIC_DIR / f"bundle-{bundle.bundle_id}.json"
    bundle_path.write_text(bundle_json)

    sat = sum(1 for m in c5_mappings if m.status == ComplianceStatus.SATISFIED)
    par = sum(1 for m in c5_mappings if m.status == ComplianceStatus.PARTIAL)
    gap = sum(1 for m in c5_mappings if m.status == ComplianceStatus.GAP)

    eval_record = {
        "id": bundle.bundle_id,
        "platform": platform,
        "workload": workload,
        "level": assurance.level.value,
        "level_label": assurance.label,
        "risk": assurance.residual_risk.value,
        "policy_decision": policy_eval.decision.value if policy_eval else None,
        "sat": sat, "par": par, "gap": gap,
        "timestamp": bundle.timestamp.isoformat(),
        "badge_path": f"/static/badge-{bundle.bundle_id}.svg",
        "bundle_path": f"/static/bundle-{bundle.bundle_id}.json",
        "c5_path": f"/static/c5-{bundle.bundle_id}.md",
    }
    evaluations.insert(0, eval_record)

    return templates.TemplateResponse(request, "result.html", {
        "request": request,
        "e": eval_record,
        "assurance": assurance,
        "policy_eval": policy_eval,
        "c5_summary": {"sat": sat, "par": par, "gap": gap},
        "level_color": _LEVEL_COLORS.get(assurance.level.value, "#6b7280"),
        "risk_color": _RISK_COLORS.get(assurance.residual_risk.value, "#6b7280"),
    })


@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    return templates.TemplateResponse(request, "verify.html", {
        "request": request,
    })


@app.post("/verify", response_class=HTMLResponse)
async def run_verify(
    request: Request,
    bundle_file: UploadFile = File(...),
):
    content = await bundle_file.read()
    try:
        data = json.loads(content.decode())
    except Exception:
        return templates.TemplateResponse(request, "verify.html", {
            "request": request,
            "error": "Invalid JSON file.",
        })

    try:
        bundle = EvidenceBundle.from_dict(data)
    except Exception as e:
        return templates.TemplateResponse(request, "verify.html", {
            "request": request,
            "error": f"Failed to parse bundle: {e}",
        })

    sig_valid = False
    if bundle.signatures:
        try:
            sig = bundle.signatures[0]
            verify_bundle = deepcopy(bundle)
            verify_bundle.signatures = []
            payload = serialize_bundle_for_signing(verify_bundle)
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig.key_id))
            public_key.verify(bytes.fromhex(sig.signature_hex), payload)
            sig_valid = True
        except Exception:
            sig_valid = False
        expires = bundle.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        expired = expires < datetime.now(timezone.utc)
        ttl_start = bundle.timestamp
        if ttl_start.tzinfo is None:
            ttl_start = ttl_start.replace(tzinfo=timezone.utc)
        ttl_hours = int((expires - ttl_start).total_seconds() / 3600)

    sat = sum(1 for m in bundle.compliance_mappings if m.status == ComplianceStatus.SATISFIED)
    par = sum(1 for m in bundle.compliance_mappings if m.status == ComplianceStatus.PARTIAL)
    gap = sum(1 for m in bundle.compliance_mappings if m.status == ComplianceStatus.GAP)

    return templates.TemplateResponse(request, "verify_result.html", {
        "request": request,
        "bundle": bundle,
        "sig_valid": sig_valid,
        "expired": expired,
        "ttl_hours": ttl_hours,
        "c5_summary": {"sat": sat, "par": par, "gap": gap},
        "level_color": _LEVEL_COLORS.get(bundle.assurance.level.value if bundle.assurance else 0, "#6b7280"),
        "risk_color": _RISK_COLORS.get(bundle.assurance.residual_risk.value if bundle.assurance else "HIGH", "#6b7280"),
    })


@app.get("/archaeology", response_class=HTMLResponse)
async def archaeology_page(request: Request):
    attacks: list[dict] = []
    if ARCHAEOLOGY_DB_PATH.exists():
        try:
            db = ArchaeologyDB(db_path=ARCHAEOLOGY_DB_PATH)
            records = db.query_attacks()
            db.close()
            for r in records:
                attacks.append({
                    "name": r.name,
                    "year": r.year,
                    "category": r.category,
                    "category_label": _CATEGORY_LABELS.get(r.category, r.category),
                    "cost": r.cost_to_attack,
                    "impact": r.impact,
                    "mitigation": r.mitigation,
                    "mitigation_difficulty": r.mitigation_difficulty,
                    "cve_id": r.cve_id or "",
                    "paper_url": r.paper_url or "",
                    "boundary_statement": r.boundary_statement,
                    "patched": r.patched,
                    "platforms": sorted(p.value for p in r.affected_platforms) if r.affected_platforms else [],
                })
        except Exception:
            pass
    categories = sorted(set(a["category"] for a in attacks))
    return templates.TemplateResponse(request, "archaeology.html", {
        "request": request,
        "attacks": attacks,
        "categories": categories,
    })


def main():
    import uvicorn
    uvicorn.run("src.web.app:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
