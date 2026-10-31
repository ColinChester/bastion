"""`bastion whoowns <path>`: find out which app owns an unfamiliar file or folder.

Built for the Phase 0 question "what is ~/.BrowserLock?" but works for any path.
Evidence gathered (all read-only):
    - what's inside, sizes, creation/modification dates, file types
    - the tail of any log files (redacted)
    - processes that have files open inside it (lsof)
    - LaunchAgents/LaunchDaemons that mention it
    - the installer package that laid it down (pkgutil), if any
    - apps whose name or bundle id resembles the folder name
    - code signature of any executables inside
"""

from __future__ import annotations

import contextlib
import plistlib
import re
from datetime import datetime
from pathlib import Path

from bastion.macos import Runner, target_user_home
from bastion.redact import Redactor


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def who_owns(path: Path, runner: Runner | None = None, home: Path | None = None) -> str:
    r = runner or Runner()
    if home is None:
        _, home = target_user_home()
    path = path.expanduser()
    if not path.is_absolute():
        path = home / path
    red = Redactor()
    out = [f"# Who owns `{path}`?", ""]
    if not path.exists():
        return "\n".join(out + ["Path does not exist."])

    keyword = re.sub(r"[^a-z0-9]", "", path.name.lower())
    st = path.stat()
    born = getattr(st, "st_birthtime", st.st_ctime)
    out += [f"- Created: {_fmt_time(born)}", f"- Last modified: {_fmt_time(st.st_mtime)}", ""]

    # Contents
    files = [p for p in path.rglob("*")] if path.is_dir() else [path]
    out += ["## Contents", ""]
    for p in sorted(files)[:40]:
        try:
            s = p.stat()
        except OSError:
            continue
        kind = "dir" if p.is_dir() else f"{s.st_size:,} bytes"
        ftype = r.run(["file", "-b", str(p)]).out.strip() if p.is_file() else ""
        out.append(f"- `{p.relative_to(path.parent)}` — {kind}, modified "
                   f"{_fmt_time(s.st_mtime)}{', ' + ftype if ftype else ''}")
    if len(files) > 40:
        out.append(f"- ...{len(files) - 40} more")
    out.append("")

    # Log tails
    logs = [p for p in files if p.is_file() and (p.suffix in (".log", ".txt", "")
                                                 and p.stat().st_size < 50_000_000)]
    for p in logs[:3]:
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        if not lines or not any(ch.isalpha() for ch in "".join(lines[:5])):
            continue
        out += [f"## Last lines of `{p.name}` (redacted)", "", "```"]
        out += [red.redact(ln)[:200] for ln in lines[-10:]]
        out += ["```", ""]

    # Open files
    res = r.run(["lsof", "+D", str(path)], timeout=30)
    procs = sorted({ln.split()[0] for ln in res.out.splitlines()[1:] if ln.strip()})
    out += ["## Processes with files open here", ""]
    out += [f"- {p}" for p in procs] or ["- none right now (run with sudo to see all processes)"]
    out.append("")

    # launchd references
    refs = []
    for d in (Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"),
              home / "Library/LaunchAgents"):
        for plist in d.glob("*.plist"):
            try:
                text = plist.read_bytes()
            except OSError:
                continue
            if path.name.encode() in text:
                try:
                    label = plistlib.loads(text).get("Label", plist.stem)
                except Exception:
                    label = plist.stem
                refs.append(f"{plist} (Label: {label})")
    out += ["## launchd jobs that mention it", ""] + ([f"- {x}" for x in refs] or ["- none"])
    out.append("")

    # Installer receipts
    receipts = set()
    for p in files[:20]:
        res = r.run(["pkgutil", "--file-info", str(p)])
        receipts.update(re.findall(r"pkgid:\s*(\S+)", res.out))
    pkgs = r.run(["pkgutil", "--pkgs"]).out.splitlines()
    receipts.update(p for p in pkgs if keyword and keyword in re.sub(r"[^a-z0-9]", "", p.lower()))
    out += ["## Installer packages", ""] + ([f"- {x}" for x in sorted(receipts)] or ["- none"])
    out.append("")

    # Similar apps
    apps = []
    for d in (Path("/Applications"), home / "Applications"):
        for app in d.glob("*.app"):
            info = app / "Contents/Info.plist"
            bid = ""
            with contextlib.suppress(Exception):
                bid = plistlib.loads(info.read_bytes()).get("CFBundleIdentifier", "")
            hay = re.sub(r"[^a-z0-9]", "", (app.name + bid).lower())
            if keyword and len(keyword) >= 4 and (keyword in hay or hay.startswith(keyword[:6])):
                apps.append(f"{app} ({bid})")
    out += ["## Apps with a similar name", ""] + ([f"- {x}" for x in apps] or ["- none"])
    out.append("")

    # Signatures of executables inside
    sigs = []
    for p in files[:200]:
        if p.is_file() and r.run(["file", "-b", str(p)]).out.startswith("Mach-O"):
            cs = r.run(["codesign", "-dv", "--verbose=2", str(p)])
            team = re.search(r"TeamIdentifier=(\S+)", cs.err)
            auth = re.search(r"Authority=(.+)", cs.err)
            sigs.append(f"`{p.name}`: team {team.group(1) if team else 'none'}, "
                        f"{auth.group(1) if auth else 'unsigned/ad-hoc'}")
    if sigs:
        out += ["## Executables inside", ""] + [f"- {s}" for s in sigs] + [""]

    verdict = "Unknown — review the evidence above."
    if procs:
        verdict = f"Most likely owned by: {', '.join(procs)} (has files open there now)."
    elif refs:
        verdict = "Most likely owned by the launchd job(s) listed above."
    elif receipts:
        verdict = f"Installed by package(s): {', '.join(sorted(receipts))}."
    elif apps:
        verdict = f"Name matches: {apps[0]}."
    out += ["## Verdict", "", verdict]
    return "\n".join(out)
