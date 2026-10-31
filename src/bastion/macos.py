"""Thin wrapper around subprocess so checks can be unit-tested with canned output."""

from __future__ import annotations

import os
import pwd
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Runner:
    def run(self, cmd: list[str], timeout: float = 30) -> Result:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return Result(p.returncode, p.stdout, p.stderr)
        except FileNotFoundError:
            return Result(127, "", f"{cmd[0]}: not found")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timed out after {timeout:.0f}s")
        except PermissionError as exc:
            return Result(126, "", str(exc))


def target_user_home() -> tuple[str, Path]:
    """The human user's name and home, even when run under sudo."""
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or pwd.getpwuid(os.getuid())[0]
    try:
        home = Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        home = Path.home()
    return user, home
