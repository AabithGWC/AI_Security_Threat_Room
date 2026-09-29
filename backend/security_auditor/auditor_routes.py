"""
auditor_routes.py — FastAPI router for the AI Security Auditor.
Mount this into your existing app.py with:
    from security_auditor.auditor_routes import auditor_router
    app.include_router(auditor_router)
"""

import json
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import StreamingResponse, JSONResponse
from ollama import Client

from .auditor_engine import stream_audit, get_resolution_confirmation, OLLAMA_API_KEY, fix_threat, revoke_threat, PATCH_DIFFS

auditor_router = APIRouter(prefix="/security", tags=["security-auditor"])

# Detect project root (one level up from this file)
PROJECT_ROOT = Path(__file__).parent.parent.resolve()


# ── SSE: stream full audit results ────────────────────────────────────────────
@auditor_router.get("/audit/stream")
async def audit_stream():
    """
    Server-Sent Events endpoint.
    The UI connects here and receives one JSON event per threat as Groq analyses it.
    """
    def event_generator():
        for event in stream_audit(PROJECT_ROOT):
            # SSE format: data: <json>\n\n
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── POST: resolve/patch all threats at once ───────────────────────────────────
@auditor_router.post("/resolve-all")
async def resolve_all_threats():
    """
    Automatically apply code patches for all security threats at once.
    """
    results = []
    for threat_id in PATCH_DIFFS.keys():
        res = fix_threat(PROJECT_ROOT, threat_id)
        results.append({"threat_id": threat_id, "result": res})
    return JSONResponse({
        "status": "success",
        "message": "All security threats resolved successfully!",
        "count": len(results),
        "details": results
    })


# ── POST: revoke/undo all threat patches at once ──────────────────────────────
@auditor_router.post("/revoke-all")
async def revoke_all_threats():
    """
    Automatically revert code patches for all security threats at once.
    """
    results = []
    for threat_id in PATCH_DIFFS.keys():
        success = revoke_threat(PROJECT_ROOT, threat_id)
        results.append({"threat_id": threat_id, "success": success})
    return JSONResponse({
        "status": "success",
        "message": "All threat patches revoked successfully!",
        "count": len(results),
        "details": results
    })


# ── POST: mark a threat as resolved, get Groq confirmation ───────────────────
@auditor_router.post("/resolve/{threat_id}")
async def resolve_threat(threat_id: str, body: dict = None):
    """
    Mark a threat as resolved.
    Returns a Groq-generated confirmation message.
    """
    title = (body or {}).get("title", threat_id)
    if not OLLAMA_API_KEY:
        return JSONResponse({"message": f"Threat '{title}' marked as resolved."})

    client = Client(
        host="https://ollama.com",
        headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"}
    )
    message = get_resolution_confirmation(client, threat_id, title)
    return JSONResponse({"threat_id": threat_id, "message": message, "status": "resolved"})


# ── POST: automatically resolve/patch a threat in the code ──────────────────
@auditor_router.post("/fix/{threat_id}")
async def fix_threat_endpoint(threat_id: str, body: dict = None):
    """
    Automatically patch the codebase to resolve the specified security threat.
    """
    res = fix_threat(PROJECT_ROOT, threat_id)
    return JSONResponse({
        "threat_id": threat_id,
        "message": res.get("message", "Patched successfully!"),
        "status": "fixed" if res.get("success") else "resolved",
        "diff_file": res.get("file_name"),
        "diff_before": res.get("before_code"),
        "diff_after": res.get("after_code")
    })


# ── POST: automatically revoke/undo a threat patch in the code ───────────────
@auditor_router.post("/revoke/{threat_id}")
async def revoke_threat_endpoint(threat_id: str, body: dict = None):
    """
    Automatically revert code patches for the specified threat.
    """
    success = revoke_threat(PROJECT_ROOT, threat_id)
    return JSONResponse({
        "threat_id": threat_id,
        "message": "Patches revoked successfully! The code is back to original state.",
        "status": "revoked" if success else "already_revoked"
    })


# ── GET: health check ─────────────────────────────────────────────────────────
@auditor_router.get("/health")
async def auditor_health():
    return JSONResponse({
        "status":       "ok",
        "ollama_ready": bool(OLLAMA_API_KEY),
        "model":        "minimax-m3:cloud",
        "threats":      6,
    })
