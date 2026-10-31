"""Posture checks (Phase 0 by hand, later run daily by the Auditor agent).

Every check is read-only. Each returns a status:
    pass / warn / fail  scored controls
    info                facts to record (versions, inventories) - not scored
    unknown             could not be measured (missing permission or tool); says why

Run with sudo for full results: `sfltool dumpbtm` needs root, and reading the privacy
(TCC) databases needs Full Disk Access for the terminal app you run it from.
Secrets found in files are reported by file, line and pattern name only - never values.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bastion.macos import Runner, target_user_home
from bastion.redact import _BUILTIN

SCORED = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    evidence: list[str] = field(default_factory=list)


class Posture:
    def __init__(self, runner: Runner | None = None, home: Path | None = None,
                 user: str | None = None):
        self.r = runner or Runner()
        if home is None:
            user, home = target_user_home()
        self.home = home
        self.user = user or home.name

    # ---- system controls ----------------------------------------------------------
    def macos_version(self) -> Check:
        res = self.r.run(["sw_vers"])
        if not res.ok:
            return Check("macos_version", "macOS version", "unknown", res.err.strip())
        vals = dict(re.findall(r"(\w+):\s*(.+)", res.out))
        v = f"{vals.get('ProductName', 'macOS')} {vals.get('ProductVersion', '?')} " \
            f"({vals.get('BuildVersion', '?')})"
        return Check("macos_version", "macOS version", "info", v)

    def filevault(self) -> Check:
        res = self.r.run(["fdesetup", "status"])
        if "FileVault is On" in res.out:
            return Check("filevault", "Disk encryption (FileVault)", "pass", "On")
        if "FileVault is Off" in res.out:
            return Check("filevault", "Disk encryption (FileVault)", "fail",
                         "Off. Turn on in System Settings > Privacy & Security > FileVault.")
        return Check("filevault", "Disk encryption (FileVault)", "unknown",
                     (res.out or res.err).strip())

    def sip(self) -> Check:
        res = self.r.run(["csrutil", "status"])
        if "enabled" in res.out.lower() and "disabled" not in res.out.lower():
            return Check("sip", "System Integrity Protection", "pass", "Enabled")
        if "disabled" in res.out.lower():
            return Check("sip", "System Integrity Protection", "fail", res.out.strip())
        return Check("sip", "System Integrity Protection", "unknown", (res.out or res.err).strip())

    def gatekeeper(self) -> Check:
        res = self.r.run(["spctl", "--status"])
        out = (res.out + res.err).lower()
        if "assessments enabled" in out:
            return Check("gatekeeper", "Gatekeeper", "pass", "Assessments enabled")
        if "assessments disabled" in out:
            return Check("gatekeeper", "Gatekeeper", "fail",
                         "Disabled. Re-enable with: sudo spctl --global-enable")
        return Check("gatekeeper", "Gatekeeper", "unknown", out.strip())

    def firewall(self) -> Check:
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        state = self.r.run([fw, "--getglobalstate"]).out.lower()
        stealth = self.r.run([fw, "--getstealthmode"]).out.lower()
        signed = self.r.run([fw, "--getallowsigned"]).out.lower()
        if not state:
            return Check("firewall", "Application firewall", "unknown",
                         "socketfilterfw gave no output")
        on = "enabled" in state and "disabled" not in state
        stealth_on = bool(re.search(r"\b(on|enabled)\b", stealth))
        auto_dl = "downloaded signed software enabled" in signed
        ev = [state.strip(), stealth.strip(), signed.strip()]
        if not on:
            return Check("firewall", "Application firewall", "fail",
                         "Firewall off. System Settings > Network > Firewall.", ev)
        if not stealth_on or auto_dl:
            why = []
            if not stealth_on:
                why.append("stealth mode off")
            if auto_dl:
                why.append("downloaded signed apps are auto-allowed")
            return Check("firewall", "Application firewall", "warn",
                         "On, but " + " and ".join(why) + ".", ev)
        return Check("firewall", "Application firewall", "pass", "On, stealth mode on", ev)

    def updates(self) -> Check:
        prefs = self.r.run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"])
        crit = re.search(r"CriticalUpdateInstall\s*=\s*(\d)", prefs.out)
        conf = re.search(r"ConfigDataInstall\s*=\s*(\d)", prefs.out)
        auto_ok = (crit is None or crit.group(1) == "1") and (conf is None or conf.group(1) == "1")
        res = self.r.run(["softwareupdate", "--list"], timeout=120)
        text = res.out + res.err
        pending = [] if "No new software available" in text else re.findall(r"\* Label: (.+)", text)
        if res.rc not in (0,) and not pending and "No new software" not in text:
            return Check("updates", "Software updates", "unknown", text.strip()[:300])
        if pending:
            status = "warn"
            detail = f"{len(pending)} update(s) pending"
        else:
            status = "pass" if auto_ok else "warn"
            detail = "Up to date" + ("" if auto_ok else "; automatic security responses are off")
        return Check("updates", "Software updates", status, detail, pending)

    def sharing(self) -> Check:
        services = {
            "Remote Login (SSH)": "com.openssh.sshd",
            "Screen Sharing": "com.apple.screensharing",
            "File Sharing (SMB)": "com.apple.smbd",
            "Remote Management": "com.apple.RemoteDesktop.agent",
        }
        disabled_out = self.r.run(["launchctl", "print-disabled", "system"]).out
        on = []
        for name, label in services.items():
            m = re.search(rf'"{re.escape(label)}"\s*=>\s*(\w+)', disabled_out)
            # "=> enabled" (or "false" on older macOS) means the service is allowed to run.
            if m and m.group(1) in ("enabled", "false"):
                on.append(name)
        if on:
            return Check("sharing", "Sharing services", "warn",
                         "Enabled: " + ", ".join(on) + ". Turn off any you don't use "
                         "(System Settings > General > Sharing).", on)
        return Check("sharing", "Sharing services", "pass", "Remote access services off")

    def listeners(self) -> Check:
        res = self.r.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if not res.ok and not res.out:
            return Check("listeners", "Listening network ports", "unknown", res.err.strip())
        exposed = set()
        for line in res.out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            addr = parts[8]
            if addr.startswith(("127.0.0.1:", "[::1]:", "localhost:")):
                continue
            exposed.add(f"{parts[0]} {addr}")
        if exposed:
            return Check("listeners", "Listening network ports", "warn",
                         f"{len(exposed)} listener(s) reachable from the network; review them.",
                         sorted(exposed))
        return Check("listeners", "Listening network ports", "pass", "Only loopback listeners")

    def background_items(self) -> Check:
        res = self.r.run(["sfltool", "dumpbtm"], timeout=60)
        if not res.ok:
            return Check("background_items", "Login and background items", "unknown",
                         "Needs root: run `sudo bastion posture`. " + res.err.strip()[:200])
        names = sorted(set(re.findall(r"^\s*Name:\s*(.+)$", res.out, re.M)))
        return Check("background_items", "Login and background items", "info",
                     f"{len(names)} named items; confirm you recognise each.", names)

    # ---- privacy grants -----------------------------------------------------------
    TCC_SERVICES = {
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServiceDeveloperTool": "Developer Tools",
    }

    def tcc(self) -> Check:
        dbs = [Path("/Library/Application Support/com.apple.TCC/TCC.db"),
               self.home / "Library/Application Support/com.apple.TCC/TCC.db"]
        grants, errors = [], []
        for db in dbs:
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                marks = ",".join("?" * len(self.TCC_SERVICES))
                q = ("SELECT service, client FROM access "
                     f"WHERE auth_value = 2 AND service IN ({marks})")
                for service, client in con.execute(q, list(self.TCC_SERVICES)):
                    grants.append(f"{self.TCC_SERVICES[service]}: {client}")
                con.close()
            except sqlite3.Error as exc:
                errors.append(f"{db}: {exc}")
        if not grants and errors:
            return Check("tcc", "Privacy grants (TCC)", "unknown",
                         "Grant Full Disk Access to your terminal app, then re-run.", errors)
        return Check("tcc", "Privacy grants (TCC)", "info",
                     f"{len(grants)} sensitive grants; remove any you no longer use.",
                     sorted(grants))

    # ---- secrets and keys ---------------------------------------------------------
    SECRET_FILES = [".netrc", ".git-credentials", ".npmrc", ".pypirc", ".env",
                    ".aws/credentials", ".aws/config", ".docker/config.json",
                    ".config/gh/hosts.yml", ".codex/config.toml", ".codex/auth.json",
                    ".claude/settings.json", ".zshrc", ".zprofile", ".zshenv", ".bashrc",
                    ".bash_profile", ".profile"]

    def secrets(self) -> Check:
        patterns = [(n, re.compile(p)) for n, p in _BUILTIN if n != "secret_assignment"]
        # The generic key=value pattern is noisy in shell files; use a stricter export form.
        patterns.append(("exported_secret", re.compile(
            r"(?i)^\s*export\s+\w*(?:token|secret|api_?key|password)\w*\s*=\s*['\"]?[^\s'\"$]{12,}")))
        found = []
        for rel in self.SECRET_FILES:
            p = self.home / rel
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                for name, rx in patterns:
                    if rx.search(line):
                        found.append(f"~/{rel}:{lineno} ({name})")
                        break
        if found:
            return Check("secrets", "Plaintext secrets in config files", "warn",
                         f"{len(found)} likely secret(s). Move them to Keychain or a password "
                         "manager CLI and rotate any that were exposed.", found)
        return Check("secrets", "Plaintext secrets in config files", "pass",
                     "None found in common config files")

    def ssh(self) -> Check:
        d = self.home / ".ssh"
        if not d.is_dir():
            return Check("ssh", "SSH keys", "pass", "No ~/.ssh folder")
        issues, keys = [], []
        for key in sorted(d.glob("id_*")):
            if key.suffix == ".pub":
                continue
            fp = self.r.run(["ssh-keygen", "-l", "-f", str(key)]).out.strip()
            keys.append(fp or key.name)
            if "RSA" in fp and fp.split()[0].isdigit() and int(fp.split()[0]) < 3072:
                issues.append(f"{key.name}: RSA key shorter than 3072 bits")
            nopass = self.r.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)])
            if nopass.ok:
                issues.append(f"{key.name}: no passphrase")
        ak = d / "authorized_keys"
        if ak.is_file() and ak.read_text().strip():
            issues.append("authorized_keys is not empty (others can SSH in if Remote Login is on)")
        if issues:
            return Check("ssh", "SSH keys", "warn", "; ".join(issues), keys)
        return Check("ssh", "SSH keys", "pass", f"{len(keys)} key(s), all passphrase-protected",
                     keys)

    # ---- apps and agents ----------------------------------------------------------
    def browser_extensions(self) -> Check:
        broad, listed = [], []
        chrome = self.home / "Library/Application Support/Google/Chrome"
        for manifest in chrome.glob("*/Extensions/*/*/manifest.json"):
            try:
                m = json.loads(manifest.read_text())
            except (OSError, ValueError):
                continue
            name = m.get("name", "?")
            if name.startswith("__MSG_"):
                name = manifest.parents[1].name
            perms = m.get("permissions", []) + m.get("host_permissions", [])
            perms = [p for p in perms if isinstance(p, str)]
            listed.append(f"Chrome: {name}")
            if any(p in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for p in perms):
                broad.append(f"Chrome: {name} (all sites)")
        ff = self.home / "Library/Application Support/Firefox/Profiles"
        for ext_json in ff.glob("*/extensions.json"):
            try:
                addons = json.loads(ext_json.read_text()).get("addons", [])
            except (OSError, ValueError):
                continue
            for a in addons:
                if a.get("location") != "app-profile" or a.get("type") != "extension":
                    continue
                name = (a.get("defaultLocale") or {}).get("name") or a.get("id")
                listed.append(f"Firefox: {name}")
                hosts = (a.get("userPermissions") or {}).get("origins", [])
                if "<all_urls>" in hosts:
                    broad.append(f"Firefox: {name} (all sites)")
        listed = sorted(set(listed))
        if broad:
            return Check("browser_extensions", "Browser extensions", "warn",
                         f"{len(broad)} of {len(listed)} extensions can read every site.",
                         sorted(set(broad)))
        return Check("browser_extensions", "Browser extensions", "pass",
                     f"{len(listed)} extensions, none with all-site access", listed)

    def ai_agents(self) -> Check:
        warn, inv = [], []
        cs = self.home / ".claude/settings.json"
        if cs.is_file():
            try:
                s = json.loads(cs.read_text())
                perms = s.get("permissions", {})
                allow = perms.get("allow", [])
                if perms.get("defaultMode") == "bypassPermissions":
                    warn.append("Claude Code: defaultMode is bypassPermissions")
                if any(a in ("Bash", "Bash(*)", "Bash(*:*)") for a in allow):
                    warn.append("Claude Code: all shell commands pre-approved")
            except ValueError:
                pass
        cj = self.home / ".claude.json"
        if cj.is_file():
            try:
                servers = json.loads(cj.read_text()).get("mcpServers", {})
                inv += [f"Claude Code MCP: {n}" for n in servers]
            except ValueError:
                pass
        cx = self.home / ".codex/config.toml"
        if cx.is_file():
            try:
                c = tomllib.loads(cx.read_text())
                if c.get("approval_policy") == "never":
                    warn.append("Codex: approval_policy = never")
                if c.get("sandbox_mode") == "danger-full-access":
                    warn.append("Codex: sandbox_mode = danger-full-access")
                inv += [f"Codex MCP: {n}" for n in c.get("mcp_servers", {})]
            except tomllib.TOMLDecodeError:
                pass
        for rel, label in ((".codeium/windsurf/mcp_config.json", "Windsurf"),
                           (".cursor/mcp.json", "Cursor")):
            p = self.home / rel
            if p.is_file():
                with contextlib.suppress(ValueError):
                    inv += [f"{label} MCP: {n}"
                            for n in json.loads(p.read_text()).get("mcpServers", {})]
        if warn:
            return Check("ai_agents", "AI coding agent settings", "warn", "; ".join(warn),
                         sorted(inv))
        return Check("ai_agents", "AI coding agent settings", "pass",
                     f"No auto-approve-everything settings; {len(inv)} MCP servers to review",
                     sorted(inv))

    def npm(self) -> Check:
        rc = self.home / ".npmrc"
        text = rc.read_text() if rc.is_file() else ""
        if re.search(r"^\s*ignore-scripts\s*=\s*true", text, re.M):
            return Check("npm", "npm install scripts", "pass", "ignore-scripts=true")
        return Check("npm", "npm install scripts", "warn",
                     "Install scripts run on every npm install. Consider `npm config set "
                     "ignore-scripts true` and allowing scripts per project.")

    # ---- run ----------------------------------------------------------------------
    def all_checks(self, skip_slow: bool = False) -> list[Check]:
        fns = [self.macos_version, self.filevault, self.sip, self.gatekeeper, self.firewall,
               self.sharing, self.listeners, self.background_items, self.tcc, self.secrets,
               self.ssh, self.browser_extensions, self.ai_agents, self.npm]
        if not skip_slow:
            fns.insert(5, self.updates)
        out = []
        for fn in fns:
            try:
                out.append(fn())
            except Exception as exc:  # one broken check must not hide the rest
                out.append(Check(fn.__name__, fn.__name__, "unknown", f"check crashed: {exc}"))
        return out


def score(checks: list[Check]) -> float | None:
    scored = [SCORED[c.status] for c in checks if c.status in SCORED]
    return round(100 * sum(scored) / len(scored)) if scored else None


def to_markdown(checks: list[Check]) -> str:
    icon = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO", "unknown": "????"}
    s = score(checks)
    lines = [f"# Bastion posture report ({time.strftime('%Y-%m-%d %H:%M')})", "",
             f"Score: **{s}/100** (pass = 1, warn = 0.5, fail = 0; info and unknown not scored)",
             "", "| Status | Control | Result |", "| --- | --- | --- |"]
    for c in checks:
        lines.append(f"| {icon[c.status]} | {c.title} | {c.detail.replace('|', '/')} |")
    for c in checks:
        if c.evidence:
            lines += ["", f"### {c.title}", ""] + [f"- {e}" for e in c.evidence[:60]]
    return "\n".join(lines)


def to_json(checks: list[Check]) -> str:
    return json.dumps({"time": int(time.time()), "score": score(checks),
                       "checks": [asdict(c) for c in checks]}, indent=2)
