"""The Bastion console: incidents (read-only) and, from Phase 3, approvals.

Server-rendered. Everything shown came from the machine's telemetry, which is untrusted
text, so templates autoescape all of it. The only script is static/passkey.js.

The approval endpoints are relays: this service holds no key that can make anything
happen. An approval or undo only works with a passkey assertion that bastiond verifies
on the Mac; registering a passkey needs a one-time code from the root CLI. Deny and
"request deletion" need no passkey because they can't release or destroy anything: deny
keeps containment in place, and a deletion request still has to be approved.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from bastion.core.corestore import CoreStore
from bastion.core.edge import EdgeError
from bastion.core.settings import Settings

TEMPLATES = Path(__file__).parent / "templates"
STATIC = Path(__file__).parent / "static"
VERDICTS = {"", "malicious", "suspicious", "inconclusive", "benign"}
_ID = re.compile(r"^[0-9a-f]{8,32}$")
JSON_BODY = Body(...)
LABELS = {
    "suspend_process": "Pause a program",
    "quarantine_file": "Move a file to quarantine",
    "disable_launch_item": "Disable a startup item",
    "delete_quarantined": "Permanently delete a quarantined file",
    "delete_disabled_item": "Permanently delete a disabled startup item",
}
STATUS = {"executed": ("active", "suspicious"), "shadow": ("shadow: not run", "inconclusive"),
          "undone": ("undone", "benign"), "deleted": ("deleted", "inconclusive"),
          "failed": ("failed", "malicious")}


def create_app(settings: Settings, store: CoreStore | None = None, edge=None,
               gateway=None) -> FastAPI:
    store = store or CoreStore(settings.db_path, settings.timezone)
    templates = Jinja2Templates(directory=str(TEMPLATES))  # autoescape on for .html
    app = FastAPI(title="Bastion", docs_url=None, redoc_url=None, openapi_url=None)

    def fmt(ms: int) -> str:
        return datetime.fromtimestamp(ms / 1000, store.tz).strftime("%b %-d, %H:%M")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, verdict: str = "", days: int = 7):
        if verdict not in VERDICTS:
            verdict = ""
        days = min(max(days, 1), 90)
        since = int(time.time() * 1000) - days * 86_400_000
        incidents = store.list_incidents(since, verdict or None)
        for i in incidents:
            i["when"] = fmt(i["created_ms"])
        hb = store.get_state("heartbeat_ms")
        age = (time.time() * 1000 - int(hb)) / 1000 if hb else None
        core_status = "never ran" if age is None else ("running" if age < 900 else "stalled")
        return templates.TemplateResponse(request, "index.html", {
            "incidents": incidents, "verdict": verdict, "days": days,
            "counts": store.verdict_counts(since), "spend_month": store.spend_month(),
            "cap_month": settings.monthly_cap_usd, "core_status": core_status})

    @app.get("/incident/{incident_id}", response_class=HTMLResponse)
    def incident(request: Request, incident_id: str):
        inc = store.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "No such incident")
        return templates.TemplateResponse(request, "incident.html", {
            "inc": inc, "when": fmt(inc.created_ms),
            "detection_json": json.dumps(inc.detection, indent=2)})

    # ---- Phase 3: approvals ---------------------------------------------------------
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    def target_of(args: dict, actions_by_id: dict) -> str:
        if "path" in args:
            return args["path"]
        ref = actions_by_id.get(args.get("action_id", ""))
        return (ref["args"].get("path", "") if ref else "") or args.get("action_id", "")

    @app.get("/approvals", response_class=HTMLResponse)
    def approvals_page(request: Request):
        ctx: dict = {"approvals": [], "actions": [], "status": None, "error": None}
        if edge is None:
            ctx["error"] = "Actions aren't set up yet (run scripts/setup-phase3.sh)."
        else:
            try:
                ctx["status"] = edge.exec_get("status")
                actions = edge.exec_get("actions", limit=40)
                by_id = {a["id"]: a for a in actions}
                for a in actions:
                    a["label"] = LABELS.get(a["action"], a["action"])
                    a["target"] = target_of(a["args"], by_id)
                    a["when"] = fmt(a["ts_ms"])
                    a["status_label"], a["css"] = STATUS.get(a["status"],
                                                             (a["status"], "inconclusive"))
                pending = edge.exec_get("approvals", status="pending")
                for p in pending:
                    p["label"] = LABELS.get(p["command"]["action"], p["command"]["action"])
                    p["target"] = target_of(p["command"]["args"], by_id)
                    p["when"] = fmt(p["created_ms"])
                ctx.update(actions=actions, approvals=pending)
                ctx["mode_banner"] = ("Automatic containment is on"
                                      if ctx["status"]["mode"] == "on"
                                      else "Shadow mode: automatic actions are only logged")
            except EdgeError as exc:
                ctx["error"] = f"Can't reach the executor on the Mac: {exc}"
        return templates.TemplateResponse(request, "approvals.html", ctx)

    @app.get("/enroll", response_class=HTMLResponse)
    def enroll_page(request: Request):
        return templates.TemplateResponse(request, "enroll.html", {})

    def guard(request: Request, item_id: str | None = None) -> None:
        """Only this console's own pages may call the API, and only with JSON."""
        if edge is None:
            raise HTTPException(503, "actions aren't set up")
        if "application/json" not in request.headers.get("content-type", ""):
            raise HTTPException(415, "JSON only")
        origin = request.headers.get("origin")
        allowed = {settings.console_url, str(request.base_url).rstrip("/")} - {""}
        if origin and origin not in allowed:
            raise HTTPException(403, "cross-origin request refused")
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")
        if item_id is not None and not _ID.match(item_id):
            raise HTTPException(400, "bad id")

    def relay(op: str, body: dict) -> dict:
        try:
            return edge.exec_post(op, body)
        except EdgeError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/enroll/options")
    def enroll_options(request: Request, body: dict = JSON_BODY):
        guard(request)
        return relay("passkey-options", {"code": str(body.get("code", ""))[:16]})

    @app.post("/api/enroll/verify")
    def enroll_verify(request: Request, body: dict = JSON_BODY):
        guard(request)
        return relay("passkey-register", {
            "code": str(body.get("code", ""))[:16],
            "challenge_id": str(body.get("challenge_id", ""))[:64],
            "credential": body.get("credential"), "name": str(body.get("name", ""))[:40]})

    @app.post("/api/{kind}/{item_id}/options")
    def passkey_options(kind: str, item_id: str, request: Request):
        guard(request, item_id)
        if kind == "approve":
            return relay("approval-options", {"approval_id": item_id})
        if kind == "undo":
            return relay("undo-options", {"action_id": item_id})
        raise HTTPException(404)

    @app.post("/api/{kind}/{item_id}/verify")
    def passkey_verify(kind: str, item_id: str, request: Request, body: dict = JSON_BODY):
        guard(request, item_id)
        proof = {"challenge_id": str(body.get("challenge_id", ""))[:64],
                 "credential": body.get("credential")}
        if kind == "approve":
            return relay("approve", {"approval_id": item_id, **proof})
        if kind == "undo":
            return relay("undo", {"action_id": item_id, **proof})
        raise HTTPException(404)

    @app.post("/api/deny/{item_id}")
    def deny(item_id: str, request: Request):
        guard(request, item_id)
        return relay("deny", {"approval_id": item_id})

    @app.post("/api/request-delete/{item_id}")
    def request_delete(item_id: str, request: Request):
        guard(request, item_id)
        if gateway is None:
            raise HTTPException(503, "the gateway isn't configured")
        try:
            result = gateway.follow_up(item_id, "requested from the console")
        except Exception as exc:
            raise HTTPException(502, "gateway unreachable") from exc
        if result.get("status") != "pending_approval":
            raise HTTPException(400, result.get("detail", "not possible"))
        return result

    return app
