"""Push notifications through ntfy.

Phase 0-1 use the public ntfy.sh server with a random, unguessable topic; Phase 4 moves
to a self-hosted server on the VM. Because ntfy.sh can read message contents, pushes
here carry only rule titles and counts, never paths, command lines or usernames.
"""

from __future__ import annotations

import logging
import time
from collections import Counter

import httpx

from bastion.config import Config
from bastion.store import Store

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, cfg: Config, client: httpx.Client | None = None):
        self.cfg = cfg.notify
        self._client = client

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.ntfy_topic) and self.cfg.mode != "off"

    def send(self, title: str, message: str, priority: str = "default",
             tags: str = "shield", click: str | None = None) -> bool:
        if not self.cfg.ntfy_topic:
            log.info("push skipped (no ntfy topic configured): %s", title)
            return False
        url = f"{self.cfg.ntfy_server.rstrip('/')}/{self.cfg.ntfy_topic}"
        headers = {"Title": title, "Priority": priority, "Tags": tags}
        if click:
            headers["Click"] = click
        try:
            client = self._client or httpx.Client(timeout=10)
            resp = client.post(url, content=message.encode(), headers=headers)
            resp.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.warning("push failed: %s", exc)
            return False


def daily_summary_text(store: Store, learning_day: int, learning_days: int,
                       sensor_health: dict[str, str], since_ms: int | None = None) -> str:
    since_ms = since_ms or int(time.time() * 1000) - 86_400_000
    dets = list(store.iter_detections(since_ms))
    by_title: Counter[str] = Counter()
    for d in dets:
        by_title[d["title"]] += d["hits"]
    lines = []
    if learning_day <= learning_days:
        lines.append(f"Shadow mode, learning day {learning_day} of {learning_days}.")
    total = sum(by_title.values())
    if total:
        lines.append(f"{total} rule hits across {len(by_title)} rules in 24 h:")
        for title, n in by_title.most_common(5):
            lines.append(f"- {title} x{n}")
        if len(by_title) > 5:
            lines.append(f"- ...and {len(by_title) - 5} more (run `bastion report`)")
    else:
        lines.append("No rule hits in the last 24 h.")
    health = ", ".join(f"{k} {v}" for k, v in sensor_health.items())
    lines.append(f"Sensors: {health}.")
    return "\n".join(lines)
