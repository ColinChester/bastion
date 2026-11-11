"""Push notifications and the daily digest (self-hosted ntfy).

The lock-screen rule from Phase 1 still holds: pushes carry headlines, verdicts and
counts, never file paths, command lines or usernames. Details live on the incident page.
"""

from __future__ import annotations

import logging
import time

import httpx

from bastion.core.corestore import CoreStore
from bastion.core.schemas import Incident, Verdict
from bastion.core.settings import Settings

log = logging.getLogger(__name__)

_PRIORITY = {"critical": "urgent", "high": "high", "medium": "default"}


class Pusher:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.s = settings
        self._client = client

    @property
    def enabled(self) -> bool:
        return bool(self.s.ntfy_url and self.s.ntfy_topic)

    def send(self, title: str, message: str, priority: str = "default",
             tags: str = "", click: str = "") -> bool:
        if not self.enabled:
            return False
        headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": priority}
        if tags:
            headers["Tags"] = tags
        if click:
            headers["Click"] = click
        try:
            client = self._client or httpx.Client(timeout=10)
            try:
                resp = client.post(f"{self.s.ntfy_url}/{self.s.ntfy_topic}",
                                   content=message.encode(), headers=headers)
                resp.raise_for_status()
            finally:
                if self._client is None:
                    client.close()
            return True
        except httpx.HTTPError as exc:
            log.warning("push failed: %s", exc)
            return False

    def incident(self, inc: Incident) -> bool:
        d = inc.decision
        icon = "rotating_light" if d.verdict == Verdict.MALICIOUS else "warning"
        body = (f"{d.verdict.value.capitalize()} ({d.confidence:.0%} confident, "
                f"{d.severity} severity). " + response_line(inc))
        page = "approvals" if any(r.status == "pending_approval" or r.follow_up_approval_id
                                  for r in inc.responses) else f"incident/{inc.id}"
        click = f"{self.s.console_url}/{page}" if self.s.console_url else ""
        return self.send(f"Bastion: {d.headline}", body,
                         priority=_PRIORITY.get(d.severity, "default"), tags=icon, click=click)


_ACTION_WORDS = {"suspend_process": "paused the program",
                 "quarantine_file": "moved the file to quarantine",
                 "disable_launch_item": "disabled the startup item"}


def response_line(inc: Incident) -> str:
    """One sentence on what Bastion did, without paths or command lines."""
    done = [r for r in inc.responses if r.status == "executed"]
    waiting = [r for r in inc.responses if r.status == "pending_approval"]
    shadow = [r for r in inc.responses if r.status == "shadow"]
    if done:
        what = " and ".join(_ACTION_WORDS.get(r.action, r.action) for r in done)
        return f"Contained: Bastion {what}. You can undo this in the console."
    if waiting:
        return "Bastion is asking to contain it: approve or deny in the console."
    if shadow:
        what = " and ".join(_ACTION_WORDS.get(r.action, r.action) for r in shadow)
        return f"Shadow mode: Bastion would have {what}. Nothing was changed."
    return "Nothing was blocked or changed. Open the incident page for details."


def digest_text(store: CoreStore, status: dict | None, settings: Settings,
                now_ms: int | None = None) -> tuple[str, str]:
    """(title, body) for the daily digest. Counts and headlines only."""
    now_ms = now_ms or int(time.time() * 1000)
    since = now_ms - 86_400_000
    counts = store.verdict_counts(since)
    total = sum(counts.values())
    lines = []
    if total:
        order = ("malicious", "suspicious", "inconclusive", "benign")
        lines.append(f"{total} detections triaged: "
                     + ", ".join(f"{counts[v]} {v}" for v in order if counts.get(v)))
        flagged = [i for i in store.list_incidents(since)
                   if i["verdict"] in ("malicious", "suspicious")]
        for i in flagged[:5]:
            lines.append(f"• {i['headline']}")
        if len(flagged) > 5:
            lines.append(f"• and {len(flagged) - 5} more")
    else:
        lines.append("No detections in the last 24 hours.")
    if status:
        stale = [n for n, age in (status.get("sensor_age_s") or {}).items()
                 if age is None or age > 900]
        hb = status.get("heartbeat_age_s")
        if hb is None or hb > 300:
            lines.append("⚠ bastiond's heartbeat is stale; check the Mac.")
        elif stale:
            lines.append("⚠ No recent data from: " + ", ".join(stale))
        else:
            ev = sum((status.get("events_24h") or {}).values())
            lines.append(f"Sensors healthy ({ev:,} events).")
    else:
        lines.append("⚠ Could not reach bastiond on the Mac.")
    lines.append(f"Model spend: ${store.spend_since(since):.2f} today, "
                 f"${store.spend_month(now_ms):.2f} of ${settings.monthly_cap_usd:.0f} "
                 "this month.")
    bad = counts.get("malicious", 0) + counts.get("suspicious", 0)
    title = (f"Bastion daily: {bad} to review" if bad else "Bastion daily: all quiet")
    return title, "\n".join(lines)
