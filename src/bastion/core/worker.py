"""The core's main loop: pull untriaged detections, run the graph, record, notify.

Delivery rules:
- A detection is acknowledged to bastiond only after its incident is saved, so a crash
  re-triages it instead of losing it (the incident table is unique per detection).
- If the model provider or bastiond is unreachable, nothing is acknowledged and the
  loop backs off; detections wait in bastiond's outbox.
- When a daily or monthly spend cap is hit, triage pauses (one push says so) and resumes
  when the period rolls over.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta

from bastion.core.corestore import CoreStore
from bastion.core.edge import Edge, EdgeError
from bastion.core.graph import triage
from bastion.core.models import ModelClient, ModelError
from bastion.core.push import Pusher, digest_text
from bastion.core.schemas import ActionResponse, Incident, Verdict
from bastion.core.settings import Settings

log = logging.getLogger(__name__)

TRIAGE_FROM = "triage_from_ms"
LAST_DIGEST = "last_digest_date"
CAP_NOTICE = "cap_notice_date"


class GatewayClient:
    """Sends proposals to the action gateway. The core holds no signing key itself."""

    def __init__(self, url: str, token: str, client=None):
        import httpx

        self._http = client or httpx.Client(base_url=url, timeout=30,
                                            headers={"Authorization": f"Bearer {token}"})

    def propose(self, body: dict) -> dict:
        resp = self._http.post("/propose", json=body)
        resp.raise_for_status()
        return resp.json()

    def follow_up(self, action_id: str, reason: str = "") -> dict:
        resp = self._http.post("/follow-up", json={"action_id": action_id, "reason": reason})
        resp.raise_for_status()
        return resp.json()


class Worker:
    def __init__(self, settings: Settings, store: CoreStore, edge: Edge, model: ModelClient,
                 pusher: Pusher | None = None, gateway=None):
        self.s, self.store, self.edge, self.model = settings, store, edge, model
        self.pusher = pusher or Pusher(settings)
        self.gateway = gateway
        if gateway is None and settings.gateway_url and settings.gateway_token:
            self.gateway = GatewayClient(settings.gateway_url, settings.gateway_token)

    def respond(self, incident: Incident) -> list[ActionResponse]:
        """Send the analyst's proposed containment to the gateway. The gateway and the
        executor decide; an unreachable gateway means nothing happens (fail closed)."""
        d = incident.decision
        if self.gateway is None or d.verdict not in (Verdict.SUSPICIOUS, Verdict.MALICIOUS):
            return []
        out: list[ActionResponse] = []
        seen: set[str] = set()
        for proposed in incident.finding.proposed_actions:
            if proposed.action in seen:
                continue
            seen.add(proposed.action)
            try:
                r = self.gateway.propose({
                    "incident_id": incident.id, "detection_id": incident.detection_id,
                    "agent": incident.domain, "action": proposed.action,
                    "verdict": d.verdict.value, "confidence": d.confidence,
                    "reason": d.headline})
            except Exception as exc:
                log.warning("gateway unreachable, no action taken: %s", exc)
                out.append(ActionResponse(action=proposed.action, status="error",
                                          detail="gateway unreachable; nothing was done"))
                continue
            out.append(ActionResponse(
                action=proposed.action, status=str(r.get("status", "error")),
                detail=str(r.get("detail", ""))[:400], policy=str(r.get("policy", "")),
                policy_ids=[str(x) for x in r.get("policy_ids", [])][:8],
                action_id=r.get("action_id"), approval_id=r.get("approval_id"),
                follow_up_approval_id=(r.get("follow_up") or {}).get("approval_id")))
        return out

    def triage_from(self) -> int:
        """Detections older than the core's first start are history, not work."""
        v = self.store.get_state(TRIAGE_FROM)
        if v is None:
            v = str(int(time.time() * 1000) - self.s.backlog_hours * 3_600_000)
            self.store.set_state(TRIAGE_FROM, v)
        return int(v)

    def over_cap(self) -> str | None:
        if self.store.spend_month() >= self.s.monthly_cap_usd:
            return f"monthly cap of ${self.s.monthly_cap_usd:.0f}"
        if self.store.spend_today() >= self.s.daily_cap_usd:
            return f"daily cap of ${self.s.daily_cap_usd:.2f}"
        return None

    def run_once(self) -> int:
        """Triage what is pending. Returns how many detections were handled."""
        cap = self.over_cap()
        if cap:
            today = datetime.now(self.store.tz).date().isoformat()
            if self.store.get_state(CAP_NOTICE) != today:
                self.store.set_state(CAP_NOTICE, today)
                self.pusher.send("Bastion: triage paused",
                                 f"Model spend reached the {cap}. Detections are still "
                                 "recorded and will be triaged when the limit resets.",
                                 tags="money_with_wings")
            return 0
        pending = self.edge.query("pending", since_ms=self.triage_from(), limit=10) or []
        done = 0
        for det in pending:
            det_id = int(det["detection_id"])
            if self.store.has_detection(det_id):  # saved before a crash; just ack it
                self.edge.ack(det_id)
                continue
            incident = triage(det, settings=self.s, model=self.model, edge=self.edge,
                              store=self.store)
            self.store.save_incident(incident)
            self.edge.ack(det_id)
            done += 1
            incident.responses = self.respond(incident)
            if incident.responses:
                self.store.save_incident(incident)
            d = incident.decision
            log.info("incident %s: %s -> %s (%.0f%%, $%.4f, %d tool calls)", incident.id,
                     incident.title, d.verdict.value, d.confidence * 100, incident.cost_usd,
                     len(incident.tool_calls))
            if d.notify:
                self.pusher.incident(incident)
            if self.over_cap():
                break
        return done

    def maybe_digest(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(self.store.tz)
        hh, mm = (int(x) for x in self.s.digest_time.split(":"))
        due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        today = now.date().isoformat()
        if now < due or self.store.get_state(LAST_DIGEST) == today:
            return False
        if now - due > timedelta(hours=6):  # started late in the day: skip, don't spam
            self.store.set_state(LAST_DIGEST, today)
            return False
        try:
            status = self.edge.query("status")
        except EdgeError:
            status = None
        title, body = digest_text(self.store, status, self.s)
        self.pusher.send(title, body, priority="low", tags="shield",
                         click=self.s.console_url)
        self.store.set_state(LAST_DIGEST, today)
        return True

    def run_forever(self) -> None:
        log.info("bastion core started: agents=%s warden=%s edge=%s", self.s.agent_model,
                 self.s.warden_model, self.s.edge_url)
        backoff = self.s.poll_seconds
        while True:
            try:
                self.run_once()
                self.maybe_digest()
                backoff = self.s.poll_seconds
            except (EdgeError, ModelError) as exc:
                backoff = min(max(backoff * 2, 30), 600)
                log.warning("%s; retrying in %d s", exc, backoff)
            except Exception:
                backoff = min(max(backoff * 2, 30), 600)
                log.exception("unexpected error in triage loop; retrying in %d s", backoff)
            self.store.set_state("heartbeat_ms", str(int(time.time() * 1000)))
            time.sleep(backoff)
