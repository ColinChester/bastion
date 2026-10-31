"""Concrete collectors: osquery results log, Santa event log, macOS unified log."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shutil

from bastion.collectors import RawRecord
from bastion.collectors.tail import FileTailer
from bastion.config import Config
from bastion.store import Store

log = logging.getLogger(__name__)


async def osquery_collector(cfg: Config, store: Store, queue: asyncio.Queue) -> None:
    """Tail osqueryd's filesystem logger output (one JSON object per line)."""
    tailer = FileTailer(cfg.osquery.results_log, "osquery", store)
    async for line in tailer.lines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            log.debug("bad osquery line: %.200s", line)
            continue
        await queue.put(RawRecord("osquery", rec))


async def santa_collector(cfg: Config, store: Store, queue: asyncio.Queue) -> None:
    """Tail Santa's event log (default `file` key=value format, or `json` if configured)."""
    tailer = FileTailer(cfg.santa.log, "santa", store)
    async for line in tailer.lines():
        await queue.put(RawRecord("santa", line))


def unified_log_command(predicates: list[str]) -> list[str]:
    combined = " OR ".join(f"({p})" for p in predicates)
    return ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate",
            combined]


async def unified_log_collector(cfg: Config, store: Store, queue: asyncio.Queue) -> None:
    """Stream matching unified-log entries via `log stream --style ndjson`.

    Restarts the subprocess with backoff if it exits. Unified log has no checkpoint:
    entries emitted while bastiond is down are not replayed (osquery and Santa cover
    the important events durably).
    """
    if not shutil.which("/usr/bin/log"):
        log.info("unified log collector disabled: /usr/bin/log not found")
        await asyncio.Event().wait()  # idle forever; returning would look like a crash
    cmd = unified_log_command(cfg.unified_log.predicates)
    backoff = 1.0
    while True:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            limit=4 * 1024 * 1024,  # default 64 KB line limit is too small for some entries
        )
        assert proc.stdout is not None
        try:
            while True:
                try:
                    raw = await proc.stdout.readline()
                except ValueError:  # one line longer than the limit: skip it
                    log.debug("skipped an oversized unified log entry")
                    continue
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if not line.startswith("{"):
                    continue  # header line ("Filtering the log data using ...")
                try:
                    await queue.put(RawRecord("unified_log", json.loads(line)))
                    backoff = 1.0
                except json.JSONDecodeError:
                    continue
        finally:
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
        await proc.wait()
        log.warning("log stream exited (%s); restarting in %.0fs", proc.returncode, backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)
