"""bastiond: the Mac edge daemon (Phase 1, shadow mode).

collectors -> normalize (OCSF) -> redact -> store -> detect -> store detections

Nothing is blocked or changed in Phase 1. Detections are stored for the
false-positive review and summarized in one daily push.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import signal
import time
from datetime import datetime, timedelta
from pathlib import Path

from bastion import __version__
from bastion.collectors import RawRecord
from bastion.collectors.sources import osquery_collector, santa_collector, unified_log_collector
from bastion.config import Config, load_config
from bastion.detect.engine import INSTALL_KEY, DetectionEngine
from bastion.normalize import Normalizer
from bastion.notify import Notifier, daily_summary_text
from bastion.redact import Redactor
from bastion.store import Store

log = logging.getLogger("bastiond")

HEARTBEAT_KEY = "heartbeat_ms"
SENSOR_STALE_MS = 15 * 60 * 1000


class Pipeline:
    """Synchronous core, shared by the daemon and `bastion replay`."""

    def __init__(self, cfg: Config, store: Store, notifier: Notifier | None = None):
        self.cfg = cfg
        self.store = store
        self.normalizer = Normalizer()
        self.redactor = Redactor(cfg.extra_redaction_patterns)
        self.engine = DetectionEngine(cfg, store)
        self.notifier = notifier
        self._last_seen_write: dict[str, float] = {}
        self.stats = {"records": 0, "events": 0, "detections": 0}

    def handle(self, rec: RawRecord) -> list[int]:
        self.stats["records"] += 1
        new_dets = []
        for ev in self.normalizer.normalize(rec):
            ev = self.redactor.redact_event(ev)
            eid = self.store.add_event(ev)
            self.stats["events"] += 1
            for hit in self.engine.evaluate(ev, eid):
                det_id, is_new = self.store.add_or_merge_detection(
                    hit.finding, hit.dedupe_key, self.cfg.detection_dedupe_seconds * 1000, eid)
                if is_new:
                    self.stats["detections"] += 1
                    new_dets.append(det_id)
                    self._maybe_live_push(hit.finding)
        self._touch_source(rec.source)
        return new_dets

    def _touch_source(self, source: str) -> None:
        now = time.time()
        if now - self._last_seen_write.get(source, 0) > 30:
            self.store.set_state(f"last_seen.{source}", str(int(now * 1000)))
            self._last_seen_write[source] = now

    def _maybe_live_push(self, finding: dict) -> None:
        if not self.notifier or self.cfg.notify.mode != "high_live":
            return
        if finding.get("severity") in ("high", "critical"):
            title = finding["finding_info"]["title"]
            self.notifier.send(f"Bastion: {title}",
                               "High-severity rule hit (shadow mode, nothing was blocked). "
                               "Details: run `sudo bastion report` on your Mac.",
                               priority="high", tags="warning")


def sensor_health(cfg: Config, store: Store, now_ms: int | None = None) -> dict[str, str]:
    now_ms = now_ms or int(time.time() * 1000)
    out = {}
    for name in ("osquery", "santa", "unified_log"):
        if not getattr(cfg, name).enabled:
            continue
        seen = store.get_state(f"last_seen.{name}")
        if seen is None:
            out[name] = "no data yet"
        elif now_ms - int(seen) > SENSOR_STALE_MS:
            out[name] = f"silent {int((now_ms - int(seen)) / 60000)} min"
        else:
            out[name] = "ok"
    return out


def learning_day(store: Store, now_ms: int | None = None) -> int:
    now_ms = now_ms or int(time.time() * 1000)
    install = int(store.get_state(INSTALL_KEY) or now_ms)
    return (now_ms - install) // 86_400_000 + 1


async def _pipeline_task(pipe: Pipeline, queue: asyncio.Queue) -> None:
    while True:
        rec = await queue.get()
        try:
            pipe.handle(rec)
        except Exception:
            log.exception("pipeline error on %s record", rec.source)


async def _heartbeat_task(cfg: Config, store: Store) -> None:
    last_purge = 0.0
    while True:
        store.set_state(HEARTBEAT_KEY, str(int(time.time() * 1000)))
        if time.time() - last_purge > 3600:
            removed = store.purge(cfg.retention_days)
            if removed:
                log.info("retention purge removed %d events", removed)
            last_purge = time.time()
        await asyncio.sleep(60)


def _next_run(hhmm: str, now: datetime) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    return target if target > now else target + timedelta(days=1)


async def _summary_task(cfg: Config, store: Store, notifier: Notifier) -> None:
    while True:
        now = datetime.now()
        wait = (_next_run(cfg.notify.daily_summary_time, now) - now).total_seconds()
        await asyncio.sleep(max(wait, 1))
        today = datetime.now().strftime("%Y-%m-%d")
        if store.get_state("last_summary_date") == today or not notifier.enabled:
            continue
        text = daily_summary_text(store, learning_day(store), cfg.baseline.learning_days,
                                  sensor_health(cfg, store))
        if notifier.send("Bastion daily summary", text, priority="low", tags="shield"):
            store.set_state("last_summary_date", today)


async def run(cfg: Config) -> None:
    store = Store(cfg.db_path)
    notifier = Notifier(cfg)
    pipe = Pipeline(cfg, store, notifier)
    queue: asyncio.Queue = asyncio.Queue(maxsize=20000)
    log.info("bastiond %s starting; %d rules loaded; data in %s", __version__,
             len(pipe.engine.rules), cfg.data_dir)
    tasks = [
        asyncio.create_task(_pipeline_task(pipe, queue), name="pipeline"),
        asyncio.create_task(_heartbeat_task(cfg, store), name="heartbeat"),
        asyncio.create_task(_summary_task(cfg, store, notifier), name="summary"),
    ]
    if cfg.osquery.enabled:
        tasks.append(asyncio.create_task(osquery_collector(cfg, store, queue), name="osquery"))
    if cfg.santa.enabled:
        tasks.append(asyncio.create_task(santa_collector(cfg, store, queue), name="santa"))
    if cfg.unified_log.enabled:
        tasks.append(asyncio.create_task(unified_log_collector(cfg, store, queue),
                                         name="unified_log"))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    stopper = asyncio.create_task(stop.wait(), name="stop")
    # Every task runs forever. If one ends (a crashed collector), exit non-zero so launchd's
    # KeepAlive restarts bastiond, instead of running on half-blind with a healthy heartbeat.
    done, _ = await asyncio.wait([stopper, *tasks], return_when=asyncio.FIRST_COMPLETED)
    failed = [t for t in done if t is not stopper]
    for t in failed:
        exc = t.exception() if not t.cancelled() else None
        log.error("task %s ended unexpectedly: %r", t.get_name(), exc,
                  exc_info=exc if exc else None)
    log.info("bastiond stopping")
    for t in [stopper, *tasks]:
        t.cancel()
    await asyncio.gather(stopper, *tasks, return_exceptions=True)
    store.close()
    if failed:
        raise SystemExit(1)


def setup_logging(log_file: Path | None, verbose: bool = False) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers = [logging.handlers.RotatingFileHandler(log_file, maxBytes=10_000_000,
                                                         backupCount=3)]
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="bastiond", description="Bastion edge daemon")
    ap.add_argument("--config", help="path to config.toml")
    ap.add_argument("--log-file", type=Path, default=Path("/Library/Logs/Bastion/bastiond.log"))
    ap.add_argument("--foreground", action="store_true", help="log to stderr instead of file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    setup_logging(None if args.foreground else args.log_file, args.verbose)
    cfg = load_config(args.config)
    asyncio.run(run(cfg))


if __name__ == "__main__":
    main()
