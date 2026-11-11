"""Phase 3 executor: signed commands, safety checks, shadow mode, rate limit, passkey
approvals bound to the stored request, undo, and the hash-chained audit log."""

from __future__ import annotations

import base64
import json
import os
import plistlib
import signal
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from softpasskey import SoftPasskey

from bastion.executor.actions import ProcInfo, Refused, clean_args
from bastion.executor.service import Executor, Rejected
from bastion.executor.store import ExecStore

RP, ORIGIN = "mac.example.ts.net", "https://mac.example.ts.net"


class FakeSystem:
    def __init__(self):
        self.procs: dict[int, ProcInfo] = {}
        self.parents: dict[int, int] = {}
        self.signals: list[tuple[int, int]] = []
        self.launchctl_calls: list[tuple] = []

    def proc_info(self, pid):
        return self.procs.get(pid)

    def parent_pid(self, pid):
        return self.parents.get(pid)

    def send_signal(self, pid, sig):
        self.signals.append((pid, sig))

    def console_uid(self):
        return 501

    def launchctl(self, *args):
        self.launchctl_calls.append(args)
        return True, ""


class Signer:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)).decode()

    def command(self, action, args, *, auto=True, key=None, **over):
        now = int(time.time() * 1000)
        cmd = {"v": 1, "id": uuid.uuid4().hex, "issued_ms": now, "expires_ms": now + 60_000,
               "action": action, "args": args, "auto": auto, "incident_id": "inc1",
               "agent": "sentry", "reason": "test", **over}
        payload = json.dumps(cmd, sort_keys=True)
        sig = (key or self.key).sign(payload.encode())
        return {"payload": payload, "sig": base64.b64encode(sig).decode()}


@pytest.fixture
def ex(cfg, tmp_path):
    signer = Signer()
    home = tmp_path / "Users" / "colin"
    (home / "Downloads").mkdir(parents=True)
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    x = cfg.executor
    x.enabled, x.command_public_key, x.rp_id, x.origin = True, signer.public, RP, ORIGIN
    x.quarantine_roots = [str(tmp_path / "Users") + "/"]
    x.user_launch_dir_pattern = "^" + str(tmp_path) + r"/Users/[^/]+/Library/LaunchAgents/"
    system = FakeSystem()
    system.procs[4000] = ProcInfo(4000, "/Users/colin/Downloads/evil", "Wed Nov 11 12:00:00 2026")
    executor = Executor(cfg, ExecStore(":memory:"), system)
    executor.signer, executor.system, executor.home = signer, system, home
    return executor


def enroll(ex) -> SoftPasskey:
    key = SoftPasskey(RP, ORIGIN)
    code = ex.new_enroll_code()
    opts = ex.register_options(code)
    ex.register_verify(code, opts["challenge_id"], key.register(opts["options"]), "phone")
    return key


SUSPEND = ("suspend_process", {"pid": 4000, "path": "/Users/colin/Downloads/evil"})


# ---- command authentication -----------------------------------------------------------

def test_shadow_mode_logs_and_changes_nothing(ex):
    r = ex.handle_command(ex.signer.command(*SUSPEND))
    assert r["status"] == "shadow" and ex.system.signals == []
    assert ex.store.get_action(r["action_id"])["status"] == "shadow"


def test_unsigned_forged_replayed_and_expired_commands_are_rejected(ex):
    ex.set_mode("on")
    good = ex.signer.command(*SUSPEND)
    with pytest.raises(Rejected, match="signature"):
        ex.handle_command({"payload": good["payload"].replace("4000", "4001"),
                           "sig": good["sig"]})
    with pytest.raises(Rejected, match="signature"):
        ex.handle_command(ex.signer.command(*SUSPEND, key=Ed25519PrivateKey.generate()))
    with pytest.raises(Rejected, match="signature"):
        ex.handle_command({"payload": good["payload"]})
    now = int(time.time() * 1000)
    with pytest.raises(Rejected, match="expired"):
        ex.handle_command(ex.signer.command(*SUSPEND, issued_ms=now - 120_000,
                                            expires_ms=now - 60_000))
    with pytest.raises(Rejected, match="expired"):   # absurdly long-lived command
        ex.handle_command(ex.signer.command(*SUSPEND, expires_ms=now + 86_400_000))
    assert ex.handle_command(good)["status"] == "executed"
    with pytest.raises(Rejected, match="replay"):
        ex.handle_command(good)
    assert ex.system.signals == [(4000, signal.SIGSTOP)]


def test_disabled_executor_rejects_everything(ex):
    ex.x.enabled = False
    with pytest.raises(Rejected, match="disabled"):
        ex.handle_command(ex.signer.command(*SUSPEND))


# ---- safety checks --------------------------------------------------------------------

def test_argument_validation():
    assert clean_args("suspend_process", {"pid": 5, "path": "/x"}) == {"pid": 5, "path": "/x"}
    for bad in ({"pid": "5", "path": "/x"}, {"pid": True, "path": "/x"}, {"pid": 5},
                {"pid": 5, "path": "/x", "cmd": "rm -rf /"}, {"pid": 5, "path": ""}, "pid=5"):
        with pytest.raises(Refused):
            clean_args("suspend_process", bad)
    with pytest.raises(Refused, match="unknown action"):
        clean_args("run_shell", {"cmd": "id"})


def test_suspend_refuses_protected_reused_and_missing_processes(ex):
    ex.set_mode("on")
    s = ex.system
    s.procs[10] = ProcInfo(10, "/usr/libexec/trustd", "x")
    s.procs[11] = ProcInfo(11, "/Applications/Thing.app/Contents/MacOS/Finder", "x")
    s.procs[12] = ProcInfo(12, "/opt/bastion/venv/bin/python", "x")
    s.parents[os.getpid()] = 77
    s.procs[77] = ProcInfo(77, "/bin/zsh", "x")
    cases = [({"pid": 10, "path": "/usr/libexec/trustd"}, "protected"),
             ({"pid": 11, "path": "/Applications/Thing.app/Contents/MacOS/Finder"}, "protected"),
             ({"pid": 12, "path": "/opt/bastion/venv/bin/python"}, "protected"),
             ({"pid": 4000, "path": "/Users/colin/other"}, "different program"),
             ({"pid": 9999, "path": "/x"}, "no longer running"),
             ({"pid": 1, "path": "/sbin/launchd"}, "refusing"),
             ({"pid": os.getpid(), "path": "/x"}, "refusing"),
             ({"pid": 77, "path": "/bin/zsh"}, "ancestor")]
    for args, why in cases:
        r = ex.handle_command(ex.signer.command("suspend_process", args))
        assert r["status"] == "refused" and why in r["detail"], (args, r)
    assert s.signals == []


def test_suspend_and_undo(ex):
    ex.set_mode("on")
    r = ex.handle_command(ex.signer.command(*SUSPEND))
    assert r["status"] == "executed"
    assert ex.undo_local(r["action_id"])["status"] == "undone"
    assert ex.system.signals == [(4000, signal.SIGSTOP), (4000, signal.SIGCONT)]
    with pytest.raises(Rejected, match="undone"):
        ex.undo_local(r["action_id"])
    # a recycled pid is never resumed
    r = ex.handle_command(ex.signer.command(*SUSPEND))
    ex.system.procs[4000] = ProcInfo(4000, "/Users/colin/Downloads/evil", "a later start")
    assert ex.undo_local(r["action_id"])["status"] == "failed"
    assert ex.system.signals.count((4000, signal.SIGCONT)) == 1


def test_quarantine_moves_file_to_vault_and_undo_restores_it(ex, cfg):
    ex.set_mode("on")
    target = ex.home / "Downloads" / "payload"
    target.write_bytes(b"malware bytes")
    target.chmod(0o755)
    r = ex.handle_command(ex.signer.command("quarantine_file", {"path": str(target)}))
    assert r["status"] == "executed" and not target.exists()
    rec = ex.store.get_action(r["action_id"])
    vault_copy = cfg.vault_dir / r["action_id"] / "payload"
    assert vault_copy.exists() and (vault_copy.stat().st_mode & 0o777) == 0
    assert rec["undo"]["size"] == 13 and len(rec["undo"]["sha256"]) == 64
    assert ex.undo_local(r["action_id"])["status"] == "undone"
    assert target.read_bytes() == b"malware bytes" and (target.stat().st_mode & 0o777) == 0o755


def test_quarantine_refuses_unsafe_targets(ex, tmp_path):
    ex.set_mode("on")
    outside = tmp_path / "etc-hosts"
    outside.write_text("x")
    link = ex.home / "Downloads" / "link"
    link.symlink_to(outside)
    ssh = ex.home / ".ssh"
    ssh.mkdir()
    (ssh / "id_ed25519").write_text("key")
    real = ex.home / "Downloads" / "f"
    real.write_text("data")
    hard = ex.home / "Downloads" / "hardlink"
    os.link(real, hard)
    cases = [(str(outside), "outside"), (str(link), "symbolic link"),
             (str(ssh / "id_ed25519"), "excluded"), (str(ex.home / "Downloads"), "regular"),
             (str(ex.home / "nope"), "not found"), ("relative/path", "absolute"),
             (str(ex.home / "Downloads" / ".." / ".ssh" / "id_ed25519"), "'..'"),
             (str(real), "hard links")]
    for path, why in cases:
        r = ex.handle_command(ex.signer.command("quarantine_file", {"path": path}))
        assert r["status"] == "refused" and why in r["detail"], (path, r)
    os.unlink(hard)
    r = ex.handle_command(ex.signer.command("quarantine_file",
                                            {"path": str(real), "sha256": "0" * 64}))
    assert r["status"] == "refused" and "hash mismatch" in r["detail"]
    assert real.exists()


def _plist(ex, name="com.evil.agent.plist", label="com.evil.agent"):
    p = ex.home / "Library" / "LaunchAgents" / name
    p.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": ["/tmp/x"]}))
    return p


def test_disable_launch_item_and_undo(ex):
    ex.set_mode("on")
    p = _plist(ex)
    r = ex.handle_command(ex.signer.command("disable_launch_item", {"path": str(p)},
                                            agent="anchor"))
    assert r["status"] == "executed" and not p.exists()
    assert p.with_name(p.name + ".disabled").exists()
    uid = os.stat(ex.home).st_uid
    assert ex.system.launchctl_calls == [("bootout", f"gui/{uid}/com.evil.agent")]
    assert ex.undo_local(r["action_id"])["status"] == "undone" and p.exists()
    assert ex.system.launchctl_calls[-1] == ("bootstrap", f"gui/{uid}", str(p))


def test_disable_refuses_protected_and_non_launch_items(ex):
    ex.set_mode("on")
    for name, label in (("com.apple.thing.plist", "com.apple.thing"),
                        ("x.plist", "com.bastion.bastiond"), ("y.plist", "io.osquery.agent")):
        r = ex.handle_command(ex.signer.command("disable_launch_item",
                                                {"path": str(_plist(ex, name, label))}))
        assert r["status"] == "refused" and "depends on" in r["detail"]
    other = ex.home / "Downloads" / "x.plist"
    other.write_bytes(plistlib.dumps({"Label": "x"}))
    r = ex.handle_command(ex.signer.command("disable_launch_item", {"path": str(other)}))
    assert r["status"] == "refused" and "not a launch agent" in r["detail"]
    assert ex.system.launchctl_calls == []


def test_rate_limit_stops_a_burst(ex):
    ex.set_mode("on")
    results = []
    for i in range(7):
        ex.system.procs[5000 + i] = ProcInfo(5000 + i, "/Users/colin/Downloads/evil", "x")
        results.append(ex.handle_command(ex.signer.command(
            "suspend_process", {"pid": 5000 + i, "path": "/Users/colin/Downloads/evil"}))
            ["status"])
    assert results == ["executed"] * 5 + ["rate_limited"] * 2
    assert len(ex.system.signals) == 5


# ---- passkeys and approvals -----------------------------------------------------------

def test_enrollment_needs_the_one_time_code(ex):
    key = SoftPasskey(RP, ORIGIN)
    with pytest.raises(Rejected, match="enrollment code"):
        ex.register_options("12345678")
    code = ex.new_enroll_code()
    with pytest.raises(Rejected, match="wrong"):
        ex.register_options("00000000" if code != "00000000" else "11111111")
    opts = ex.register_options(code)
    ex.register_verify(code, opts["challenge_id"], key.register(opts["options"]))
    assert len(ex.store.list_passkeys()) == 1
    with pytest.raises(Rejected, match="enrollment code"):   # the code is single-use
        ex.register_options(code)


def test_enrollment_code_locks_after_five_wrong_tries(ex):
    code = ex.new_enroll_code()
    wrong = "00000000" if code != "00000000" else "11111111"
    for _ in range(5):
        with pytest.raises(Rejected):
            ex.register_options(wrong)
    with pytest.raises(Rejected, match="no valid enrollment code"):
        ex.register_options(code)


def test_tier2_always_waits_for_a_passkey_even_if_marked_automatic(ex):
    ex.set_mode("on")
    key = enroll(ex)
    target = ex.home / "Downloads" / "payload"
    target.write_bytes(b"x")
    q = ex.handle_command(ex.signer.command("quarantine_file", {"path": str(target)}))
    r = ex.handle_command(ex.signer.command("delete_quarantined",
                                            {"action_id": q["action_id"]}, auto=True))
    assert r["status"] == "pending_approval"
    vault = ex.cfg.vault_dir / q["action_id"]
    assert vault.exists()
    opts = ex.approval_options(r["approval_id"])
    done = ex.approve(r["approval_id"], opts["challenge_id"], key.sign(opts["options"]))
    assert done["status"] == "executed" and not vault.exists()
    assert ex.store.get_action(q["action_id"])["status"] == "deleted"
    with pytest.raises(Rejected, match="deleted"):       # nothing left to restore
        ex.undo_local(q["action_id"])
    with pytest.raises(Rejected, match="already"):       # approvals are single-use
        ex.approval_options(r["approval_id"])


def test_approval_gated_containment_runs_even_in_shadow_mode(ex):
    key = enroll(ex)
    r = ex.handle_command(ex.signer.command(*SUSPEND, auto=False))
    assert r["status"] == "pending_approval" and ex.system.signals == []
    opts = ex.approval_options(r["approval_id"])
    assert ex.approve(r["approval_id"], opts["challenge_id"],
                      key.sign(opts["options"]))["status"] == "executed"
    assert ex.system.signals == [(4000, signal.SIGSTOP)]


def test_bad_passkey_responses_are_rejected(ex):
    key = enroll(ex)
    stranger = SoftPasskey(RP, ORIGIN)
    a = ex.handle_command(ex.signer.command(*SUSPEND, auto=False))["approval_id"]
    ex.system.procs[4001] = ProcInfo(4001, "/Users/colin/Downloads/other", "x")
    b = ex.handle_command(ex.signer.command(
        "suspend_process", {"pid": 4001, "path": "/Users/colin/Downloads/other"},
        auto=False))["approval_id"]

    def attempt(approval, challenge_id, credential, why):
        with pytest.raises(Rejected, match=why):
            ex.approve(approval, challenge_id, credential)

    o = ex.approval_options(a)
    attempt(a, o["challenge_id"], stranger.sign(o["options"]), "unknown passkey")
    o = ex.approval_options(a)
    attempt(a, o["challenge_id"], key.sign(o["options"], origin="https://evil.example"),
            "passkey check failed")
    o = ex.approval_options(a)
    no_uv = SoftPasskey(RP, ORIGIN, user_verified=False)
    no_uv.key, no_uv.cred_id = key.key, key.cred_id
    attempt(a, o["challenge_id"], no_uv.sign(o["options"]), "passkey check failed")
    # a signature made for approval A can't approve B
    oa, ob = ex.approval_options(a), ex.approval_options(b)
    signed_a = key.sign(oa["options"])
    attempt(b, oa["challenge_id"], signed_a, "expired or already used")
    attempt(b, ob["challenge_id"], signed_a, "passkey check failed")
    # a used challenge can't be replayed
    o = ex.approval_options(a)
    cred = key.sign(o["options"])
    assert ex.approve(a, o["challenge_id"], cred)["status"] == "executed"
    attempt(a, o["challenge_id"], cred, "already")
    assert ex.system.signals == [(4000, signal.SIGSTOP)]


def test_approval_executes_the_stored_request_not_the_callers(ex):
    key = enroll(ex)
    r = ex.handle_command(ex.signer.command(*SUSPEND, auto=False))
    stored = ex.store.get_approval(r["approval_id"])["command"]
    assert stored["args"] == {"pid": 4000, "path": "/Users/colin/Downloads/evil"}
    opts = ex.approval_options(r["approval_id"])
    cred = key.sign(opts["options"])
    cred["args"] = {"pid": 1}                     # extra fields from a caller are ignored
    ex.approve(r["approval_id"], opts["challenge_id"], cred)
    assert ex.system.signals == [(4000, signal.SIGSTOP)]


def test_deny_and_expiry(ex):
    enroll(ex)
    r = ex.handle_command(ex.signer.command(*SUSPEND, auto=False))
    assert ex.deny(r["approval_id"])["status"] == "denied"
    with pytest.raises(Rejected, match="denied"):
        ex.approve_local(r["approval_id"])
    r = ex.handle_command(ex.signer.command(*SUSPEND, auto=False))
    ex.store.db.execute("UPDATE approvals SET expires_ms = 1 WHERE id = ?",
                        (r["approval_id"],))
    with pytest.raises(Rejected, match="expired"):
        ex.approve_local(r["approval_id"])
    assert ex.system.signals == []


def test_undo_from_the_console_needs_the_passkey(ex):
    ex.set_mode("on")
    key = enroll(ex)
    r = ex.handle_command(ex.signer.command(*SUSPEND))
    opts = ex.undo_options(r["action_id"])
    with pytest.raises(Rejected):
        ex.undo(r["action_id"], opts["challenge_id"], SoftPasskey(RP, ORIGIN).sign(
            opts["options"]))
    opts = ex.undo_options(r["action_id"])
    assert ex.undo(r["action_id"], opts["challenge_id"],
                   key.sign(opts["options"]))["status"] == "undone"


# ---- audit log ------------------------------------------------------------------------

def test_audit_log_is_chained_and_detects_tampering(ex):
    ex.set_mode("on")
    ex.handle_command(ex.signer.command(*SUSPEND))
    ex.handle_command(ex.signer.command("suspend_process", {"pid": 1, "path": "/sbin/launchd"}))
    ok, n, _ = ex.store.verify_audit()
    assert ok and n >= 3
    kinds = [e["kind"] for e in ex.store.audit_tail()]
    assert "action_executed" in kinds and "command_refused" in kinds
    ex.store.db.execute("UPDATE audit SET body = replace(body, '4000', '4001') "
                        "WHERE kind = 'action_executed'")
    ok, _, detail = ex.store.verify_audit()
    assert not ok and "contents changed" in detail
    ex2 = ExecStore(":memory:")
    ex2.audit("a", {}), ex2.audit("b", {}), ex2.audit("c", {})
    ex2.db.execute("DELETE FROM audit WHERE seq = 2")
    assert ex2.verify_audit()[0] is False


def test_status_reports_mode_and_shadow_day(ex):
    st = ex.status()
    assert st["mode"] == "shadow" and st["shadow_day"] == 1 and st["passkeys"] == 0
    ex.set_mode("on")
    assert ex.status()["mode"] == "on"
