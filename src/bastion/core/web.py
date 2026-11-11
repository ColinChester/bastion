"""Read-only incident page (Phase 2).

Server-rendered, no JavaScript, no write endpoints. Everything shown came from the
machine's telemetry, which is untrusted text, so templates autoescape all of it.
The full console (approvals, live view) replaces this in later phases.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from bastion.core.corestore import CoreStore
from bastion.core.settings import Settings

TEMPLATES = Path(__file__).parent / "templates"
VERDICTS = {"", "malicious", "suspicious", "inconclusive", "benign"}


def create_app(settings: Settings, store: CoreStore | None = None) -> FastAPI:
    store = store or CoreStore(settings.db_path, settings.timezone)
    templates = Jinja2Templates(directory=str(TEMPLATES))  # autoescape on for .html
    app = FastAPI(title="Bastion", docs_url=None, redoc_url=None, openapi_url=None)

    def fmt(ms: int) -> str:
        return datetime.fromtimestamp(ms / 1000, store.tz).strftime("%b %-d, %H:%M")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'")
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

    return app
