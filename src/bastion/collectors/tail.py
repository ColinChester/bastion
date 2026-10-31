"""Rotation-aware file tailer with a persistent checkpoint.

Polling (rather than kqueue) keeps this simple, portable and testable; a 1 s poll on a
couple of log files costs nothing measurable. The checkpoint (inode + byte offset) is
saved in the store, so a restart resumes where it left off instead of re-reading or
skipping lines.

Rotation handling: if the inode changes or the file shrinks below the saved offset,
the remainder of the old file is lost (newsyslog has already moved it) and reading
restarts at offset 0 of the new file.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator

from bastion.store import Store

log = logging.getLogger(__name__)


class FileTailer:
    def __init__(
        self,
        path: str,
        checkpoint_name: str,
        store: Store,
        poll_seconds: float = 1.0,
        start_at_end_if_new: bool = True,
    ):
        self.path = path
        self.name = checkpoint_name
        self.store = store
        self.poll = poll_seconds
        self.start_at_end_if_new = start_at_end_if_new
        self._buf = b""

    def read_available(self) -> list[str]:
        """Read all complete lines appended since the last call. Never blocks."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        inode, offset = self.store.get_checkpoint(self.name)
        if inode is None and self.start_at_end_if_new:
            # First run: don't replay an existing multi-megabyte log as "new" events.
            self.store.set_checkpoint(self.name, st.st_ino, st.st_size)
            return []
        if inode != st.st_ino or st.st_size < offset:
            log.info("%s rotated or truncated; restarting at 0", self.path)
            offset = 0
            self._buf = b""
        if st.st_size == offset:
            if inode != st.st_ino:
                self.store.set_checkpoint(self.name, st.st_ino, offset)
            return []
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read(8 * 1024 * 1024)  # cap per poll; the rest comes next poll
            new_offset = fh.tell()
        data = self._buf + chunk
        lines = data.split(b"\n")
        self._buf = lines.pop()  # incomplete trailing line (or b"")
        # Persist offset excluding the buffered partial line so a crash re-reads it.
        self.store.set_checkpoint(self.name, st.st_ino, new_offset - len(self._buf))
        self._buf = b""
        return [ln.decode("utf-8", errors="replace") for ln in lines if ln.strip()]

    async def lines(self) -> AsyncIterator[str]:
        while True:
            try:
                batch = self.read_available()
            except OSError as exc:  # permission errors, transient I/O
                log.warning("tail %s failed: %s", self.path, exc)
                batch = []
            for line in batch:
                yield line
            if not batch:
                await asyncio.sleep(self.poll)
