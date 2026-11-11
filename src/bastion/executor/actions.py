"""The actions the executor can take, and the safety checks each one enforces.

Tier 1 actions contain a threat and can be undone exactly. Tier 2 actions finish the job
permanently and can only run with a passkey approval. Every action:

- takes typed arguments (anything else is rejected before a check runs)
- has `check`, which decides whether the target is allowed, with no side effects
- has `execute`, which re-runs `check` and returns what `undo` needs

Checks are deliberately independent of the orchestrator and gateway. Whatever asked for
the action, a protected process is never suspended and a file outside the allowed
folders is never moved.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import plistlib
import re
import shutil
import signal
import stat
from dataclasses import dataclass
from pathlib import Path

from bastion.config import ExecutorConfig
from bastion.macos import Runner

TIERS: dict[str, int] = {
    "suspend_process": 1,
    "quarantine_file": 1,
    "disable_launch_item": 1,
    "delete_quarantined": 2,
    "delete_disabled_item": 2,
}

ARG_SPECS: dict[str, dict[str, type]] = {
    "suspend_process": {"pid": int, "path": str},
    "quarantine_file": {"path": str},
    "disable_launch_item": {"path": str},
    "delete_quarantined": {"action_id": str},
    "delete_disabled_item": {"action_id": str},
}
OPTIONAL_ARGS: dict[str, dict[str, type]] = {"quarantine_file": {"sha256": str}}


class Refused(Exception):
    """A safety check said no. Nothing was changed."""


class Failed(Exception):
    """The action was allowed but could not be completed."""


def clean_args(action: str, args: dict) -> dict:
    """Exactly the declared arguments, with the declared types. Raises Refused."""
    if action not in TIERS:
        raise Refused(f"unknown action {action!r}")
    if not isinstance(args, dict):
        raise Refused("arguments must be an object")
    spec, optional = ARG_SPECS[action], OPTIONAL_ARGS.get(action, {})
    extra = set(args) - set(spec) - set(optional)
    if extra:
        raise Refused(f"unexpected argument(s): {', '.join(sorted(extra))}")
    out = {}
    for key, typ in {**spec, **optional}.items():
        if key not in args:
            if key in spec:
                raise Refused(f"missing argument: {key}")
            continue
        value = args[key]
        if typ is int and (isinstance(value, bool) or not isinstance(value, int)):
            raise Refused(f"{key} must be an integer")
        if typ is str and (not isinstance(value, str) or not value or len(value) > 1024
                           or "\x00" in value):
            raise Refused(f"{key} must be a non-empty string")
        out[key] = value
    return out


@dataclass
class ProcInfo:
    pid: int
    path: str
    started: str


class System:
    """The few operating-system operations actions need. Faked in tests."""

    def __init__(self, runner: Runner | None = None):
        self.runner = runner or Runner()

    def proc_info(self, pid: int) -> ProcInfo | None:
        r = self.runner.run(["/bin/ps", "-o", "lstart=,comm=", "-p", str(pid)], timeout=5)
        line = r.out.strip()
        if not r.ok or not line:
            return None
        parts = line.split(None, 5)  # lstart is five fields: "Wed Nov 11 12:00:00 2026"
        if len(parts) < 6:
            return None
        return ProcInfo(pid, parts[5], " ".join(parts[:5]))

    def parent_pid(self, pid: int) -> int | None:
        r = self.runner.run(["/bin/ps", "-o", "ppid=", "-p", str(pid)], timeout=5)
        try:
            return int(r.out.strip())
        except ValueError:
            return None

    def send_signal(self, pid: int, sig: int) -> None:
        os.kill(pid, sig)

    def console_uid(self) -> int | None:
        try:
            return os.stat("/dev/console").st_uid
        except OSError:
            return None

    def launchctl(self, *args: str) -> tuple[bool, str]:
        r = self.runner.run(["/bin/launchctl", *args], timeout=20)
        return r.ok, (r.err or r.out).strip()[:300]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Actions:
    def __init__(self, cfg: ExecutorConfig, vault_dir: Path, system: System | None = None,
                 own_pid: int | None = None):
        self.cfg = cfg
        self.vault = Path(vault_dir)
        self.sys = system or System()
        self.own_pid = own_pid or os.getpid()

    # ---- shared checks ------------------------------------------------------------
    def _protected_path(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.cfg.protected_path_prefixes)

    def _real_file(self, raw: str) -> Path:
        """Resolve a path and require a regular file that isn't reached via a symlink."""
        if not raw.startswith("/") or "/../" in raw or raw.endswith("/.."):
            raise Refused("path must be absolute, without '..'")
        p = Path(raw)
        try:
            st = os.lstat(p)
        except OSError as exc:
            raise Refused(f"file not found ({exc.strerror})") from exc
        if stat.S_ISLNK(st.st_mode):
            raise Refused("target is a symbolic link")
        if not stat.S_ISREG(st.st_mode):
            raise Refused("target is not a regular file")
        # Folder symlinks (/tmp -> /private/tmp) are resolved; callers check the real path.
        return Path(os.path.realpath(p))

    # ---- suspend_process ----------------------------------------------------------
    def _check_suspend(self, args: dict) -> ProcInfo:
        pid = args["pid"]
        if pid <= 1 or pid == self.own_pid:
            raise Refused("refusing to touch this process id")
        ancestor = self.own_pid  # never freeze anything Bastion itself runs under
        for _ in range(16):
            ancestor = self.sys.parent_pid(ancestor) if ancestor else None
            if not ancestor or ancestor <= 1:
                break
            if ancestor == pid:
                raise Refused("target is an ancestor of bastiond")
        info = self.sys.proc_info(pid)
        if info is None:
            raise Refused("process is no longer running")
        if info.path != args["path"]:
            raise Refused("the process id now belongs to a different program")
        if Path(info.path).name in self.cfg.protected_process_names:
            raise Refused(f"{Path(info.path).name} is on the protected-process list")
        if self._protected_path(info.path):
            raise Refused("program is in a protected system or security-tool location")
        return info

    def _do_suspend(self, args: dict) -> tuple[str, dict]:
        info = self._check_suspend(args)
        try:
            self.sys.send_signal(info.pid, signal.SIGSTOP)
        except OSError as exc:
            raise Failed(f"could not suspend pid {info.pid}: {exc.strerror}") from exc
        return (f"suspended pid {info.pid}",
                {"pid": info.pid, "path": info.path, "started": info.started})

    def _undo_suspend(self, undo: dict) -> str:
        info = self.sys.proc_info(undo["pid"])
        if info is None:
            raise Failed("process has already exited; nothing to resume")
        if info.path != undo["path"] or info.started != undo["started"]:
            raise Failed("the process id now belongs to a different program; not resuming it")
        try:
            self.sys.send_signal(undo["pid"], signal.SIGCONT)
        except OSError as exc:
            raise Failed(f"could not resume pid {undo['pid']}: {exc.strerror}") from exc
        return f"resumed pid {undo['pid']}"

    # ---- quarantine_file ----------------------------------------------------------
    def _check_quarantine(self, args: dict) -> tuple[Path, os.stat_result]:
        real = self._real_file(args["path"])
        text = str(real)
        if not any(text.startswith(root) for root in self.cfg.quarantine_roots):
            raise Refused("file is outside the folders Bastion may quarantine from")
        if self._protected_path(text) or text.startswith(str(self.vault) + "/"):
            raise Refused("file is in a protected location")
        if any(marker in text for marker in self.cfg.quarantine_excludes):
            raise Refused("file is in an excluded location (keys, mail, photos, Bastion data)")
        st = os.lstat(real)
        if st.st_size > self.cfg.max_quarantine_bytes:
            raise Refused("file is larger than the quarantine size limit")
        if st.st_nlink > 1:
            raise Refused("file has other hard links")
        want = args.get("sha256")
        if want and sha256_file(real) != want.lower():
            raise Refused("file contents changed since the detection (hash mismatch)")
        return real, st

    def _do_quarantine(self, args: dict, action_id: str) -> tuple[str, dict]:
        real, st = self._check_quarantine(args)
        digest = sha256_file(real)
        slot = self.vault / action_id
        slot.mkdir(parents=True, mode=0o700)
        self.vault.chmod(0o700)
        dest = slot / "payload"
        try:
            try:
                os.rename(real, dest)
            except OSError:  # different volume: copy, then remove the original
                shutil.copy2(real, dest, follow_symlinks=False)
                os.unlink(real)
            if os.lstat(dest).st_ino != st.st_ino and sha256_file(dest) != digest:
                # Not the file that was checked (the path was swapped mid-move): put it back.
                with contextlib.suppress(OSError):
                    os.rename(dest, real)
                    slot.rmdir()
                raise Failed("file changed while it was being moved; it was put back")
            os.chmod(dest, 0)
        except OSError as exc:
            with contextlib.suppress(OSError):
                slot.rmdir()
            raise Failed(f"could not move the file: {exc.strerror}") from exc
        return (f"moved to the quarantine vault (sha256 {digest[:16]}…)",
                {"original": str(real), "vault": str(dest), "mode": stat.S_IMODE(st.st_mode),
                 "uid": st.st_uid, "gid": st.st_gid, "sha256": digest, "size": st.st_size})

    def _undo_quarantine(self, undo: dict) -> str:
        src, dest = Path(undo["vault"]), Path(undo["original"])
        if not src.exists():
            raise Failed("the quarantined copy is gone (already deleted?)")
        if os.path.lexists(dest):
            raise Failed("a file now exists at the original location; not overwriting it")
        if not dest.parent.is_dir():
            raise Failed("the original folder no longer exists")
        try:
            os.chmod(src, undo["mode"])
            try:
                os.rename(src, dest)
            except OSError:
                shutil.copy2(src, dest)
                os.unlink(src)
            with contextlib.suppress(OSError):
                os.chown(dest, undo["uid"], undo["gid"])
            with contextlib.suppress(OSError):
                src.parent.rmdir()
        except OSError as exc:
            raise Failed(f"could not restore the file: {exc.strerror}") from exc
        return f"restored to {dest}"

    # ---- disable_launch_item ------------------------------------------------------
    def _check_launch_item(self, args: dict) -> tuple[Path, str, str]:
        real = self._real_file(args["path"])
        text = str(real)
        in_system = any(text.startswith(d) for d in self.cfg.launch_dirs)
        in_user = re.match(self.cfg.user_launch_dir_pattern, text) is not None
        if not (in_system or in_user) or not text.endswith(".plist"):
            raise Refused("not a launch agent or daemon property list")
        try:
            with open(real, "rb") as fh:
                label = plistlib.load(fh).get("Label", "")
        except Exception as exc:
            raise Refused("could not read the property list") from exc
        if not isinstance(label, str) or not label:
            label = real.stem
        if any(label.startswith(p) or real.name.startswith(p)
               for p in self.cfg.protected_label_prefixes):
            raise Refused(f"{label} belongs to macOS or a security tool Bastion depends on")
        if "/LaunchDaemons/" in text:
            domain = "system"
        else:
            uid = os.stat(real.parents[2]).st_uid if in_user else self.sys.console_uid()
            if uid is None:
                raise Refused("could not determine which user this agent belongs to")
            domain = f"gui/{uid}"
        return real, label, domain

    def _do_disable(self, args: dict) -> tuple[str, dict]:
        real, label, domain = self._check_launch_item(args)
        disabled = real.with_name(real.name + ".disabled")
        if os.path.lexists(disabled):
            raise Failed("a disabled copy already exists")
        ok, msg = self.sys.launchctl("bootout", f"{domain}/{label}")
        try:
            os.rename(real, disabled)
        except OSError as exc:
            raise Failed(f"could not rename the property list: {exc.strerror}") from exc
        note = "unloaded" if ok else "was not loaded"
        return (f"{label} {note} and renamed to {disabled.name}",
                {"original": str(real), "disabled": str(disabled), "label": label,
                 "domain": domain, "was_loaded": ok, "launchctl": msg})

    def _undo_disable(self, undo: dict) -> str:
        src, dest = Path(undo["disabled"]), Path(undo["original"])
        if not src.exists():
            raise Failed("the disabled property list is gone (already deleted?)")
        if os.path.lexists(dest):
            raise Failed("a file now exists at the original location; not overwriting it")
        try:
            os.rename(src, dest)
        except OSError as exc:
            raise Failed(f"could not rename the property list back: {exc.strerror}") from exc
        if not undo.get("was_loaded"):
            return f"restored {dest.name} (it was not loaded before, so it was not started)"
        ok, msg = self.sys.launchctl("bootstrap", undo["domain"], str(dest))
        return f"restored {dest.name}" + ("" if ok else f"; could not reload it ({msg})")

    # ---- tier 2 -------------------------------------------------------------------
    def _contained(self, store, action_id: str, kind: str) -> dict:
        rec = store.get_action(action_id)
        if rec is None or rec["action"] != kind:
            raise Refused("no matching containment action")
        if rec["status"] != "executed":
            raise Refused(f"that containment is {rec['status']}, not active")
        return rec

    def _do_delete_quarantined(self, args: dict, store) -> tuple[str, dict]:
        rec = self._contained(store, args["action_id"], "quarantine_file")
        slot = Path(rec["undo"]["vault"]).parent
        if slot.parent != self.vault:
            raise Refused("vault record points outside the vault")
        try:
            payload = slot / "payload"
            if payload.exists():
                os.chmod(payload, 0o600)
            shutil.rmtree(slot)
        except OSError as exc:
            raise Failed(f"could not delete the quarantined file: {exc.strerror}") from exc
        store.set_action_status(rec["id"], "deleted")
        return f"permanently deleted the quarantined copy of {rec['undo']['original']}", {}

    def _do_delete_disabled(self, args: dict, store) -> tuple[str, dict]:
        rec = self._contained(store, args["action_id"], "disable_launch_item")
        target = Path(rec["undo"]["disabled"])
        if not target.name.endswith(".plist.disabled"):
            raise Refused("record does not point at a disabled property list")
        try:
            target.unlink()
        except OSError as exc:
            raise Failed(f"could not delete {target.name}: {exc.strerror}") from exc
        store.set_action_status(rec["id"], "deleted")
        return f"permanently deleted {target.name}", {}

    # ---- public interface ---------------------------------------------------------
    def check(self, action: str, args: dict, store=None) -> None:
        """Raise Refused if this action must not run on this target. No side effects."""
        if action == "suspend_process":
            self._check_suspend(args)
        elif action == "quarantine_file":
            self._check_quarantine(args)
        elif action == "disable_launch_item":
            self._check_launch_item(args)
        elif action == "delete_quarantined":
            self._contained(store, args["action_id"], "quarantine_file")
        elif action == "delete_disabled_item":
            self._contained(store, args["action_id"], "disable_launch_item")
        else:
            raise Refused(f"unknown action {action!r}")

    def execute(self, action: str, args: dict, action_id: str, store=None) -> tuple[str, dict]:
        """Run the action. Returns (what happened, undo record)."""
        if action == "suspend_process":
            return self._do_suspend(args)
        if action == "quarantine_file":
            return self._do_quarantine(args, action_id)
        if action == "disable_launch_item":
            return self._do_disable(args)
        if action == "delete_quarantined":
            return self._do_delete_quarantined(args, store)
        if action == "delete_disabled_item":
            return self._do_delete_disabled(args, store)
        raise Refused(f"unknown action {action!r}")

    def undo(self, action: str, undo: dict) -> str:
        if action == "suspend_process":
            return self._undo_suspend(undo)
        if action == "quarantine_file":
            return self._undo_quarantine(undo)
        if action == "disable_launch_item":
            return self._undo_disable(undo)
        raise Refused("this action cannot be undone")
