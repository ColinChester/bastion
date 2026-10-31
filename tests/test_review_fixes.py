"""Regression tests for problems found while running Bastion on a real Mac."""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from conftest import exec_cols, norm, oq

from bastion import cli, daemon
from bastion.collectors import RawRecord
from bastion.collectors.tail import FileTailer
from bastion.config import ConfigPermissionError
from bastion.daemon import HEARTBEAT_KEY, Pipeline
from bastion.detect.sigma import load_rules
from bastion.doctor import _ingest_checks
from bastion.posture import Posture
from bastion.store import Store

# ---- CLI without sudo -----------------------------------------------------------------


def _deny_config(path=None):
    raise ConfigPermissionError("can't read config.toml (root-only)")


def test_cli_without_sudo_explains_instead_of_crashing(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", _deny_config)
    assert cli.main(["report", "--out", "x.md"]) == 1
    assert "sudo bastion report" in capsys.readouterr().err


def test_cli_rules_works_without_sudo(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", _deny_config)
    assert cli.main(["rules"]) == 0
    assert "15 rules loaded, 0 errors" in capsys.readouterr().out


def test_store_commands_need_root(monkeypatch, cfg):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    with pytest.raises(SystemExit) as exc:
        cli._store(cfg, "status")
    assert "sudo bastion status" in str(exc.value)


def test_report_file_is_handed_back_to_sudo_user(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda p, u, g: calls.append((str(p), u, g)))
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    out = tmp_path / "reports" / "fp.md"
    cli._write_user_file(out, "hello")
    assert out.read_text() == "hello"
    assert calls == [(str(out), 501, 20)]


# ---- daemon supervision ---------------------------------------------------------------


def test_daemon_exits_nonzero_when_a_collector_crashes(cfg, monkeypatch):
    async def boom(*_):
        raise RuntimeError("collector died")

    async def idle(*_):
        await asyncio.Event().wait()

    monkeypatch.setattr(daemon, "osquery_collector", boom)
    monkeypatch.setattr(daemon, "santa_collector", idle)
    monkeypatch.setattr(daemon, "unified_log_collector", idle)
    with pytest.raises(SystemExit) as exc:
        asyncio.run(daemon.run(cfg))
    assert exc.value.code == 1


# ---- doctor checks the feed, not just the processes -----------------------------------


def test_doctor_ingest_checks(cfg):
    now = time.time()
    st = Store(cfg.db_path)
    st.set_state(HEARTBEAT_KEY, str(int(now * 1000)))
    st.set_state("last_seen.osquery", str(int((now - 20) * 1000)))
    st.set_state("last_seen.santa", str(int((now - 3600) * 1000)))
    st.close()
    items = {h.component: h for h in _ingest_checks(cfg, now)}
    assert "ingest" not in items  # heartbeat fresh
    assert items["osquery feed"].status == "ok"
    assert items["santa feed"].status == "fail"


def test_doctor_flags_stale_heartbeat(cfg):
    now = time.time()
    st = Store(cfg.db_path)
    st.set_state(HEARTBEAT_KEY, str(int((now - 900) * 1000)))
    st.close()
    items = {h.component: h for h in _ingest_checks(cfg, now)}
    assert items["ingest"].status == "fail"


# ---- detection semantics --------------------------------------------------------------


def test_first_exec_batch_is_evaluated_not_treated_as_snapshot(cfg, store):
    pipe = Pipeline(cfg, store)
    rec = oq("process_events",
             exec_cols("/usr/sbin/spctl", "spctl --master-disable", platform=1), counter=0)
    pipe.handle(RawRecord("osquery", rec))
    assert [d["title"] for d in store.iter_detections()] == ["Gatekeeper Disabled With spctl"]


def test_state_query_snapshot_still_skipped(cfg, store):
    pipe = Pipeline(cfg, store)
    rec = oq("launchd", {"path": "/Library/LaunchAgents/com.vendor.x.plist",
                         "label": "com.vendor.x", "program": "/x"}, counter=0)
    pipe.handle(RawRecord("osquery", rec))
    assert list(store.iter_detections()) == []


def test_same_file_write_from_es_and_fsevents_merges(cfg, store):
    pipe = Pipeline(cfg, store)
    target = "/Users/colin/Library/LaunchAgents/com.evil.agent.plist"
    pipe.handle(RawRecord("osquery", oq("file_events", {
        "pid": "7", "path": "/usr/bin/python3", "filename": target, "dest_filename": "",
        "event_type": "create", "time": "1793480000"})))
    pipe.handle(RawRecord("osquery", oq("fs_events", {"target_path": target,
                                                      "action": "CREATED"})))
    dets = list(store.iter_detections())
    assert len(dets) == 1 and dets[0]["hits"] == 2


def _file_open(target, proc):
    return norm(oq("file_events", {"pid": "9", "path": proc, "filename": target,
                                   "dest_filename": "", "event_type": "open",
                                   "time": "1793480000"}))


@pytest.mark.parametrize("proc", [
    "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/"
    "Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
    "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
    "/opt/bastion/python/cpython-3.12.16-macos-aarch64-none/bin/python3.12",
])
def test_credential_rule_ignores_browsers_and_own_tools(proc):
    rules, _ = load_rules(cli.Config().resolved_rules_dir())
    rule = next(r for r in rules if r.title.startswith("Credential Store Opened"))
    target = "/Users/colin/Library/Application Support/Google/Chrome/Default/Cookies"
    assert not rule.matches(_file_open(target, proc))
    assert rule.matches(_file_open(target, "/private/tmp/stealer"))


# ---- collectors -----------------------------------------------------------------------


def test_tailer_skips_a_line_longer_than_the_read_cap(tmp_path, store, monkeypatch):
    import bastion.collectors.tail as tail

    monkeypatch.setattr(tail, "_MAX_READ", 16)
    log = tmp_path / "x.log"
    log.write_text("")
    t = FileTailer(str(log), "x", store)
    assert t.read_available() == []  # first run starts at the end
    log.write_text("A" * 40 + "\nok\n")
    batches = [t.read_available() for _ in range(5)]
    assert ["ok"] in batches


# ---- posture --------------------------------------------------------------------------


def test_tool_token_files_flagged_only_when_readable_by_others(tmp_path):
    auth = tmp_path / ".codex" / "auth.json"
    auth.parent.mkdir()
    auth.write_text('{"id_token": "eyJhbGciOi.eyJzdWIiOiJ4.c2lnbmF0dXJlMTIz"}')
    auth.chmod(0o600)
    p = Posture(home=tmp_path, user="colin")
    assert p.secrets().status == "pass"
    auth.chmod(0o644)
    chk = p.secrets()
    assert chk.status == "warn" and "chmod 600" in chk.evidence[0]
