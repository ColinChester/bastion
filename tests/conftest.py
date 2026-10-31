from __future__ import annotations

import pytest

from bastion.collectors import RawRecord
from bastion.config import Config
from bastion.normalize import Normalizer
from bastion.store import Store


@pytest.fixture
def cfg(tmp_path) -> Config:
    c = Config()
    c.data_dir = tmp_path / "data"
    return c


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


def oq(name: str, columns: dict, action: str = "added", counter: int = 5) -> dict:
    """An osquery differential result line."""
    return {"name": name, "hostIdentifier": "mac", "unixTime": 1793480000,
            "counter": counter, "action": action, "columns": columns}


def exec_cols(path: str, cmdline: str = "", *, team_id: str = "", platform: int = 0,
              flags: str = "", parent_path: str = "/bin/zsh", parent_cmdline: str = "-zsh",
              pid: int = 4242) -> dict:
    return {"event_type": "exec", "pid": str(pid), "parent": "100", "path": path,
            "cmdline": cmdline or path, "cwd": "/Users/colin", "uid": "501",
            "username": "colin", "signing_id": "", "team_id": team_id, "cdhash": "",
            "platform_binary": str(platform), "codesigning_flags": flags,
            "parent_path": parent_path, "parent_cmdline": parent_cmdline,
            "env": "AWS_SECRET_ACCESS_KEY=abc123abc123abc123", "time": "1793480000"}


def norm(record: dict, source: str = "osquery") -> dict:
    events = Normalizer().normalize(RawRecord(source, record))
    assert len(events) == 1, events
    return events[0]
