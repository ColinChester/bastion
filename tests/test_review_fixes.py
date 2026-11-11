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


# ---- findings from the first day of real data -----------------------------------------


def _launchd(path, label, counter=5):
    return RawRecord("osquery", oq("launchd", {"path": path, "label": label,
                                               "program": "/x"}, counter=counter))


def test_known_launch_item_reported_again_does_not_alert(cfg, store):
    pipe = Pipeline(cfg, store)
    item = ("/Library/LaunchAgents/us.zoom.updater.plist", "us.zoom.updater")
    pipe.handle(_launchd(*item, counter=0))  # snapshot: learned, silent
    pipe.handle(_launchd(*item))             # osquery re-reports it as "added"
    assert list(store.iter_detections()) == []
    pipe.handle(_launchd("/Library/LaunchAgents/com.evil.x.plist", "com.evil.x"))
    dets = list(store.iter_detections())
    assert len(dets) == 1
    from bastion.report import build_report
    assert "(com.evil.x)" in build_report(store)


def test_ephemeral_and_loopback_listeners_share_one_baseline_key(cfg, store):
    pipe = Pipeline(cfg, store)
    store.set_state("install_ms", "0")  # learning window over
    store.baseline_touch("listener", "/usr/libexec/rapportd:ephemeral", 0)

    def listen(port, addr="0.0.0.0"):
        return RawRecord("osquery", oq("listening_ports", {
            "pid": "5", "port": str(port), "protocol": "6", "address": addr,
            "path": "/usr/libexec/rapportd"}))

    pipe.handle(listen(59866))
    pipe.handle(listen(61012))
    pipe.handle(listen(8080, "127.0.0.1"))
    assert list(store.iter_detections()) == []
    pipe.handle(listen(445))
    assert [d["title"] for d in store.iter_detections()] == [
        "First-seen listening port for this binary"]


def test_gh_cli_keychain_read_is_filtered():
    rules, _ = load_rules(cli.Config().resolved_rules_dir())
    rule = next(r for r in rules if r.title.startswith("Keychain Secrets"))
    cmd = "/usr/bin/security find-generic-password -s gh:github.com -wa ColinChester"
    gh = norm(oq("process_events", exec_cols(
        "/usr/bin/security", cmd, platform=1,
        parent_path="/opt/homebrew/Cellar/gh/2.80.0/bin/gh", parent_cmdline="gh auth token")))
    other = norm(oq("process_events", exec_cols(
        "/usr/bin/security", "security find-generic-password -s 'Chrome Safe Storage' -wa x",
        platform=1, parent_path="/private/tmp/stealer")))
    assert not rule.matches(gh)
    assert rule.matches(other)


# ---- shadow-week review (Nov 11) ------------------------------------------------------


def _rule(title_prefix):
    rules, _ = load_rules(cli.Config().resolved_rules_dir())
    return next(r for r in rules if r.title.startswith(title_prefix))


def test_safari_import_service_reading_browser_logins_is_benign():
    svc = ("/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/"
           "XPCServices/com.apple.Safari.BrowserDataImportingService.xpc/Contents/MacOS/"
           "com.apple.Safari.BrowserDataImportingService")
    target = "/Users/colin/Library/Application Support/Google/Chrome/Default/Login Data"
    rule = _rule("Credential Store Opened")
    assert not rule.matches(_file_open(target, svc))
    # a look-alike name outside the system volume is still flagged
    assert rule.matches(_file_open(target, "/tmp/com.apple.Safari.BrowserDataImportingService"))


def test_nuget_compiler_in_hidden_folder_is_benign():
    rule = _rule("Binary Executed From a Hidden Folder")
    ilc = ("/Users/colin/.nuget/packages/runtime.osx-arm64.microsoft.dotnet.ilcompiler/"
           "10.0.14/tools/ilc")
    assert not rule.matches(norm(oq("process_events", exec_cols(ilc, f"{ilc} @x.rsp"))))
    assert rule.matches(norm(oq("process_events", exec_cols("/Users/colin/.hidden/x"))))


def test_zoom_updater_plist_is_benign():
    rule = _rule("LaunchAgent or LaunchDaemon Property List Written")
    zoom = "/Users/colin/Library/LaunchAgents/us.zoom.updater.gui.501.app.terminate.update.plist"
    ev = norm(oq("fs_events", {"target_path": zoom, "action": "CREATED"}))
    assert not rule.matches(ev)


def test_report_marks_trigger_test_hits_as_real(cfg, store):
    from bastion.report import build_report

    pipe = Pipeline(cfg, store)
    d = "/Users/colin/git/bastion/build/decoys"
    pipe.handle(RawRecord("osquery", oq("process_events", exec_cols(
        f"{d}/spctl", f"{d}/spctl --master-disable", flags="ADHOC"))))
    assert "[x] real" in build_report(store) and "(trigger test)" in build_report(store)


def test_gh_parent_resolved_from_santa_before_osquery_reports_child(cfg, store):
    """Real sequence from Nov 11: gh exits before osquery's 10 s batch, so osquery's
    row for `security` has no parent path. Santa saw gh exec first."""
    pipe = Pipeline(cfg, store)
    gh = "/opt/homebrew/Cellar/gh/2.103.3/bin/gh"
    pipe.handle(RawRecord("santa", (
        "[2026-11-11T17:35:00.939Z] I santad: action=EXEC|decision=ALLOW|reason=UNKNOWN|"
        f"pid=84693|pidversion=1|ppid=84657|uid=501|user=colin|mode=M|path={gh}|"
        "args=gh auth token")))
    cmd = "/usr/bin/security find-generic-password -s gh:github.com -wa ColinChester"
    cols = exec_cols("/usr/bin/security", cmd, platform=1, pid=84714, parent_path="",
                     parent_cmdline="")
    cols["parent"] = "84693"
    pipe.handle(RawRecord("osquery", oq("process_events", cols)))
    assert list(store.iter_detections()) == []


def test_browser_updaters_clearing_quarantine_are_benign():
    rule = _rule("Quarantine Attribute Removed")
    keystone = ("/bin/bash -p /var/folders/zt/x/T/com.google.GoogleUpdater.GoogleUpdater_chrome_"
                "Unpacker_BeginUnzipping.HXkM7x/.keystone_install /var/folders/zt/x/T/com.google."
                "GoogleUpdater.GoogleUpdater_chrome_Unpacker_BeginUnzipping.HXkM7x "
                "\"/Applications/Google Chrome.app\" 156.0.8078.80")
    chrome = norm(oq("process_events", exec_cols(
        "/usr/bin/xattr", 'xattr -d -r com.apple.quarantine "/Applications/Google Chrome.app"',
        platform=1, parent_path="/bin/bash", parent_cmdline=keystone)))
    mozilla = ("/Applications/Firefox.app/Contents/MacOS/updater.app/Contents/MacOS/"
               "org.mozilla.updater")
    firefox = norm(oq("process_events", exec_cols(
        "/usr/bin/xattr", "/usr/bin/xattr -dr com.apple.quarantine /Applications/Firefox.app",
        platform=1, parent_path=mozilla, parent_cmdline=mozilla + " 3 /x")))
    by_hand = norm(oq("process_events", exec_cols(
        "/usr/bin/xattr", 'xattr -d -r com.apple.quarantine "/Applications/Google Chrome.app"',
        platform=1, parent_path="/bin/zsh", parent_cmdline="-zsh")))
    assert not rule.matches(chrome)
    assert not rule.matches(firefox)
    assert rule.matches(by_hand)
