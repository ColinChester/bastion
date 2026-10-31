import json
import time

from bastion.doctor import check_all
from bastion.macos import Result
from bastion.posture import Posture, score, to_markdown
from bastion.triage import who_owns


class FakeRunner:
    def __init__(self, table: dict[str, Result]):
        self.table = table
        self.calls = []

    def run(self, cmd, timeout=30):
        self.calls.append(cmd)
        key = " ".join(cmd)
        for prefix, res in self.table.items():
            if key.startswith(prefix):
                return res
        return Result(1, "", "not stubbed")


def ok(out="", err=""):
    return Result(0, out, err)


GOOD_MAC = {
    "sw_vers": ok("ProductName:\tmacOS\nProductVersion:\t26.1\nBuildVersion:\t25B78\n"),
    "fdesetup status": ok("FileVault is On.\n"),
    "csrutil status": ok("System Integrity Protection status: enabled.\n"),
    "spctl --status": ok("assessments enabled\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate":
        ok("Firewall is enabled. (State = 1)\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode":
        ok("Firewall stealth mode is on\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned":
        ok("Automatically allow downloaded signed software DISABLED.\n"),
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate":
        ok("{\n    ConfigDataInstall = 1;\n    CriticalUpdateInstall = 1;\n}\n"),
    "softwareupdate --list": ok("", "No new software available.\n"),
    "launchctl print-disabled system": ok('\t"com.openssh.sshd" => disabled\n'),
    "lsof -nP -iTCP -sTCP:LISTEN": ok(
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "node 1 c 20u IPv4 0x1 0t0 TCP 127.0.0.1:5173 (LISTEN)\n"),
    "sfltool dumpbtm": ok("  Name: LuLu\n  Name: Parallels Desktop\n"),
}


def test_posture_good_mac(tmp_path):
    p = Posture(FakeRunner(GOOD_MAC), home=tmp_path, user="colin")
    checks = {c.id: c for c in p.all_checks()}
    for cid in ("filevault", "sip", "gatekeeper", "firewall", "updates", "sharing",
                "listeners", "secrets", "ssh"):
        assert checks[cid].status == "pass", (cid, checks[cid])
    assert checks["macos_version"].detail.startswith("macOS 26.1")
    assert checks["background_items"].evidence == ["LuLu", "Parallels Desktop"]
    assert checks["npm"].status == "warn"
    assert "Score:" in to_markdown(list(checks.values()))


def test_posture_bad_mac(tmp_path):
    bad = dict(GOOD_MAC)
    bad["fdesetup status"] = ok("FileVault is Off.\n")
    bad["/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"] = \
        ok("Firewall stealth mode is off\n")
    bad["launchctl print-disabled system"] = ok('"com.openssh.sshd" => enabled\n')
    bad["lsof -nP -iTCP -sTCP:LISTEN"] = ok(
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "python3 1 c 3u IPv4 0x1 0t0 TCP *:8000 (LISTEN)\n")
    (tmp_path / ".zshrc").write_text("export OPENAI_API_KEY=sk-proj-" + "x" * 40 + "\n")
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh/id_ed25519").write_text("key")
    bad["ssh-keygen -l"] = ok("256 SHA256:abc colin@mac (ED25519)\n")
    bad["ssh-keygen -y"] = ok("ssh-ed25519 AAAA\n")  # succeeded with empty passphrase
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps(
        {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}))
    checks = {c.id: c for c in Posture(FakeRunner(bad), home=tmp_path).all_checks()}
    assert checks["filevault"].status == "fail"
    assert checks["firewall"].status == "warn"
    assert checks["sharing"].status == "warn"
    assert checks["listeners"].evidence == ["python3 *:8000"]
    assert checks["secrets"].status == "warn"
    assert checks["secrets"].evidence[0].startswith("~/.zshrc:1")
    assert "x" * 40 not in json.dumps(checks["secrets"].evidence)
    assert "no passphrase" in checks["ssh"].detail
    assert checks["ai_agents"].status == "warn"
    assert score(list(checks.values())) < 100


def test_posture_unknown_without_permissions(tmp_path):
    checks = {c.id: c for c in Posture(FakeRunner({}), home=tmp_path).all_checks(
        skip_slow=True)}
    assert checks["background_items"].status == "unknown"
    assert checks["filevault"].status == "unknown"


def test_doctor_reports_missing_fda(cfg, tmp_path):
    log = tmp_path / "results.log"
    old = int(time.time()) - 3600
    log.write_text(json.dumps({"name": "process_events", "unixTime": old}) + "\n")
    cfg.osquery.results_log = str(log)
    runner = FakeRunner({"pgrep -x osqueryd": ok("1"),
                         "santactl status": ok(">>> Daemon Info\n  Mode | Monitor\n"),
                         "pgrep -f LuLu": ok("2"), "pgrep -f BlockBlock": ok("3"),
                         "pgrep -f bastiond": ok("4")})
    items = {h.component: h for h in check_all(cfg, runner)}
    assert items["osquery"].status == "fail" and "Full Disk Access" in items["osquery"].fix
    assert items["santa"].status == "ok"
    assert items["notify"].status == "warn"


def test_whoowns_reports_contents_and_verdict(tmp_path):
    target = tmp_path / ".BrowserLock"
    (target / "log").mkdir(parents=True)
    (target / "log/app.log").write_text("started\nlocked chrome token=abcdefghijk123\n")
    runner = FakeRunner({"file -b": ok("ASCII text"),
                         "lsof +D": ok("COMMAND PID\nBrowserLockAgent 99 c\n")})
    md = who_owns(target, runner=runner, home=tmp_path)
    assert "app.log" in md
    assert "abcdefghijk123" not in md  # log tail is redacted
    assert "BrowserLockAgent" in md.split("## Verdict")[1]
