#!/usr/bin/env python3
"""Read-only view of the Bastion Oracle VM and its tenancy.

Run by .github/workflows/oracle-inspect.yml.

Usage: oracle-inspect.py QUERY
  check        the VM against what docs/oracle-vm.md expects; exit 1 on a mismatch
  instance     state, shape, OCPUs, memory, boot volume
  image        OS and version of the boot image
  network      private/public IP and the subnet's ingress rules
  ssh-key      fingerprints of the authorized SSH keys (never the keys)
  cloud-init   whether user_data is set, its size and SHA-256 (never the contents)
  agent        Oracle Cloud Agent plugin status
  metrics      7-day p95 CPU and memory, daily network, against the idle-reclaim line
  limits       A1 OCPUs and memory used vs. the tenancy limit
  stack        the Resource Manager stack's recent jobs
  job-log      the log of one stack job (JOB_ID), redacted
  audit        write operations in the tenancy over AUDIT_HOURS (default 24)
  cloud-guard  open Cloud Guard problems
  budget       budgets and spend
  backups      boot volume backups
  watch        check + metrics + audit + cloud-guard (the daily run); exit 1 on a problem
  all          everything except job-log

The query set is fixed; nothing here can change the tenancy, and the OCI user it runs as only
has inspect/read rights. The repository is public, so Actions logs are public: every line
printed goes through redact(), which removes keys and user_data and shortens OCIDs, IPs and
email addresses.

Env: OCI (the CLI, default "oci"), OCI_COMPARTMENT_ID (the tenancy OCID), OCI_INSTANCE_NAME
(default bastion-vm), OCI_STACK_ID (stack and job-log), JOB_ID, AUDIT_HOURS, EXPECT_* (check).
Exit: 0 fine, 1 a check failed, 2 a query or setup error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

OCI = os.environ.get("OCI", "oci")
RECLAIM_LINE = 20.0  # Oracle reclaims Always Free VMs whose 7-day p95 stays under 20%

# Policy statement each query needs, quoted in the hint when OCI says "not authorized".
POLICY = {
    "instance": "read instance-family",
    "image": "read instance-family",
    "network": "read virtual-network-family",
    "agent": "read instance-agent-plugins",
    "metrics": "read metrics",
    "limits": "read resource-availability",
    "stack": "read orm-family",
    "job-log": "read orm-family",
    "audit": "read audit-events",
    "cloud-guard": "read cloud-guard-family",
    "budget": "read usage-budgets",
    "backups": "read volume-family",
}


class OciError(Exception):
    pass


# ---------------------------------------------------------------- redaction

_PRIVATE_V4 = re.compile(r"^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
_REDACTIONS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<private key redacted>"),
    (re.compile(r"tskey-[A-Za-z0-9_-]+"), "tskey-<redacted>"),
    (re.compile(r"""(["']?(?:user_data|ssh_authorized_keys)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)"""),
     lambda m: f'{m.group(1)}"<redacted>"'),
    (re.compile(r"(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)\s+"
                r"[A-Za-z0-9+/]{40,}={0,3}(?:\s+\S+)?"),
     "<ssh public key: see the ssh-key query>"),
    (re.compile(r"[A-Za-z0-9+/]{120,}={0,3}"), lambda m: f"<base64 redacted, {len(m[0])} chars>"),
    (re.compile(r"\bocid1\.([a-z0-9]+)\.[A-Za-z0-9._-]+"),
     lambda m: f"ocid1.{m[1]}…{m[0][-6:]}"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
     lambda m: f"…@{m[1]}"),
    (re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"),
     lambda m: m[0] if _PRIVATE_V4.match(m[0]) else f"{m[1]}.{m[2]}.x.x"),
]


def redact(text: str) -> str:
    """Make text safe for a public log. Applied to every line this script prints."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


_out: list[str] = []


def say(line: str = "") -> None:
    line = redact(line)
    _out.append(line)
    print(line, flush=True)


# ---------------------------------------------------------------- OCI calls

def oci(*args: str) -> dict:
    """Run one OCI CLI command and return its JSON. Only the fixed calls below use this."""
    proc = subprocess.run([OCI, *args], capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        msg = "\n".join(x for x in (proc.stderr.strip(), proc.stdout.strip()) if x)
        raise OciError(msg or f"oci exited {proc.returncode}")
    out = proc.stdout.strip()
    return json.loads(out) if out else {}


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise OciError(f"{name} is not set")
    return value


def compartment() -> str:
    return env("OCI_COMPARTMENT_ID")


_instance_cache: dict | None = None


def find_instance() -> dict | None:
    """The newest non-terminated instance named OCI_INSTANCE_NAME, or None."""
    global _instance_cache
    if _instance_cache is None:
        name = os.environ.get("OCI_INSTANCE_NAME") or "bastion-vm"
        data = oci("compute", "instance", "list", "--compartment-id", compartment(),
                   "--display-name", name, "--all").get("data") or []
        live = [i for i in data if i.get("lifecycle-state") not in ("TERMINATED", "TERMINATING")]
        live.sort(key=lambda i: (i.get("time-created") or ""), reverse=True)
        _instance_cache = live[0] if live else {}
    return _instance_cache or None


def require_instance() -> dict:
    inst = find_instance()
    if not inst:
        raise NoInstance(os.environ.get("OCI_INSTANCE_NAME") or "bastion-vm")
    return inst


class NoInstance(Exception):
    pass


def metadata(inst: dict) -> dict:
    return inst.get("metadata") or {}


def ssh_fingerprints(keys: str) -> list[str]:
    """OpenSSH-style SHA256 fingerprints of an authorized_keys blob."""
    fps = []
    for line in keys.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except ValueError:
            fps.append("<unparseable key>")
            continue
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        fps.append(f"SHA256:{digest} ({parts[0]})")
    return fps


def cloud_init_facts(inst: dict) -> dict:
    raw = metadata(inst).get("user_data")
    if not raw:
        return {"set": False}
    try:
        text = base64.b64decode(raw).decode("utf-8", "replace")
    except ValueError:
        return {"set": True, "decodable": False}
    return {
        "set": True,
        "decodable": True,
        "bytes": len(text.encode()),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "cloud_config": text.lstrip().startswith("#cloud-config"),
        "placeholder": "__TAILSCALE_AUTHKEY__" in text,
        "tailscale_key": "tskey-" in text,
    }


def image_of(inst: dict) -> dict:
    image_id = (inst.get("source-details") or {}).get("image-id")
    if not image_id:
        return {}
    return oci("compute", "image", "get", "--image-id", image_id).get("data") or {}


def vnics_of(inst: dict) -> list[dict]:
    return oci("compute", "instance", "list-vnics", "--instance-id", inst["id"],
               "--compartment-id", compartment()).get("data") or []


def _port_range(rule: dict) -> str:
    for key in ("tcp-options", "udp-options"):
        rng = (rule.get(key) or {}).get("destination-port-range")
        if rng:
            lo, hi = rng.get("min"), rng.get("max")
            return str(lo) if lo == hi else f"{lo}-{hi}"
    return "all"


PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "all": "all"}


def ingress_rules(subnet_id: str) -> list[str]:
    subnet = oci("network", "subnet", "get", "--subnet-id", subnet_id).get("data") or {}
    rules = []
    for sl_id in subnet.get("security-list-ids") or []:
        sl = oci("network", "security-list", "get", "--security-list-id", sl_id).get("data") or {}
        for rule in sl.get("ingress-security-rules") or []:
            proto = PROTOCOLS.get(str(rule.get("protocol")), str(rule.get("protocol")))
            rules.append(f"{proto} {_port_range(rule)} from {rule.get('source')}")
    return rules


# ---------------------------------------------------------------- queries

def q_instance() -> int:
    inst = require_instance()
    cfg = inst.get("shape-config") or {}
    src = inst.get("source-details") or {}
    say(f"instance    {inst.get('display-name')}  {inst.get('lifecycle-state')}  "
        f"created {(inst.get('time-created') or '?')[:16]}  {inst.get('availability-domain')}")
    say(f"id          {inst.get('id')}")
    say(f"shape       {inst.get('shape')}  ocpus={cfg.get('ocpus')}  "
        f"memory_gb={cfg.get('memory-in-gbs')}")
    say(f"boot volume {src.get('boot-volume-size-in-gbs', 'default')} GB")
    return 0


def q_image() -> int:
    img = image_of(require_instance())
    say(f"image       {(img.get('display-name') or '?')}  ({(img.get('operating-system') or '?')} "
        f"{(img.get('operating-system-version') or '?')})")
    return 0


def q_network() -> int:
    for vnic in vnics_of(require_instance()):
        say(f"vnic        private={vnic.get('private-ip')}  "
            f"public={vnic.get('public-ip') or 'none'}")
        for rule in ingress_rules(vnic["subnet-id"]):
            say(f"ingress     {rule}")
    return 0


def q_ssh_key() -> int:
    keys = metadata(require_instance()).get("ssh_authorized_keys") or ""
    fps = ssh_fingerprints(keys)
    for fp in fps:
        say(f"ssh-key     {fp}")
    if not fps:
        say("ssh-key     none")
    return 0


def q_cloud_init() -> int:
    facts = cloud_init_facts(require_instance())
    if not facts["set"]:
        say("cloud-init  not set")
    elif not facts["decodable"]:
        say("cloud-init  set, but not valid base64")
    else:
        say(f"cloud-init  set  {facts['bytes']} bytes  sha256={facts['sha256']}")
        say(f"            #cloud-config={'yes' if facts['cloud_config'] else 'NO'}  "
            f"placeholder left={'YES' if facts['placeholder'] else 'no'}  "
            f"tailscale key={'yes' if facts['tailscale_key'] else 'no'}")
        say("            compare: shasum -a 256 deploy/vm/stack.local/cloud-init.local.yaml")
    return 0


def q_agent() -> int:
    inst = require_instance()
    data = oci("instance-agent", "plugin", "list", "--compartment-id", compartment(),
               "--instanceagent-id", inst["id"], "--all").get("data") or []
    for p in sorted(data, key=lambda p: (p.get("name") or "")):
        msg = f"  ({p['message']})" if p.get("message") else ""
        say(f"agent       {(p.get('status') or '?'):<10} {p.get('name')}{msg}")
    if not data:
        say("agent       no plugins reported (agent not running yet?)")
    return 0


def _metric(inst: dict, query: str, start: datetime, end: datetime) -> list[float]:
    resp = oci("monitoring", "metric-data", "summarize-metrics-data",
               "--compartment-id", compartment(), "--namespace", "oci_computeagent",
               "--query-text", query, "--start-time", start.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ"))
    values: list[float] = []
    for series in resp.get("data") or []:
        values += [float(p["value"]) for p in series.get("aggregated-datapoints") or []]
    return values


def p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]


def metric_report() -> list[str]:
    """Problems found; also prints the figures."""
    inst = require_instance()
    end = datetime.now(UTC).replace(second=0, microsecond=0)
    start = end - timedelta(days=7)
    rid = inst["id"]
    problems = []
    for label, name in (("cpu", "CpuUtilization"), ("memory", "MemoryUtilization")):
        vals = _metric(inst, f'{name}[5m]{{resourceId = "{rid}"}}.mean()', start, end)
        value = p95(vals)
        if value is None:
            say(f"metrics     {label:<7} p95 7d: no data (agent monitoring plugin off, or new VM)")
            continue
        flag = "" if value >= RECLAIM_LINE else f"  ← under the {RECLAIM_LINE:.0f}% reclaim line"
        say(f"metrics     {label:<7} p95 7d: {value:5.1f}%{flag}")
        if flag:
            problems.append(f"{label} p95 {value:.1f}% is under the idle-reclaim line")
    for label, name in (("net in", "NetworksBytesIn"), ("net out", "NetworksBytesOut")):
        vals = _metric(inst, f'{name}[1d]{{resourceId = "{rid}"}}.sum()', start, end)
        if vals:
            say(f"metrics     {label:<7} {sum(vals) / len(vals) / 1e6:9.1f} MB/day (7d avg)")
    return problems


def q_metrics() -> int:
    metric_report()
    return 0


def q_limits() -> int:
    """A1 limits are per availability domain: the VM's, or every AD when there's no VM."""
    inst = find_instance()
    if inst:
        ads = [inst["availability-domain"]]
    else:
        ads = [a["name"] for a in oci("iam", "availability-domain", "list", "--compartment-id",
                                      compartment()).get("data") or []]
    for ad in ads:
        for label, limit, unit in (("ocpus", "standard-a1-core-count", ""),
                                   ("memory", "standard-a1-memory-count", " GB")):
            d = oci("limits", "resource-availability", "get", "--compartment-id", compartment(),
                    "--service-name", "compute", "--limit-name", limit,
                    "--availability-domain", ad).get("data") or {}
            used, avail = d.get("used"), d.get("available")
            total = (used or 0) + (avail or 0) if None not in (used, avail) else "?"
            say(f"limits      {ad.split(':')[-1]}  A1 {label:<6} used {used}{unit} of "
                f"{total}{unit}")
    return 0


def q_stack() -> int:
    data = stack_jobs()
    for job in data or []:
        say(f"stack job   {(job.get('time-created') or '?')[:16]}  "
            f"{job.get('operation') or '?':<8} "
            f"{job.get('lifecycle-state') or '?':<11} {job.get('id')}")
    if not data:
        say("stack job   none")
    return 0


JOB_ID = re.compile(r"^ocid1\.ormjob\.[A-Za-z0-9._-]+$")
SUMMARY_LINE = re.compile(r"(Plan: .*|Apply complete!.*|No changes\..*|Error: .*)")


LATEST = {"latest": None, "latest-apply": "APPLY", "latest-plan": "PLAN"}


def stack_jobs() -> list[dict]:
    return oci("resource-manager", "job", "list", "--stack-id", env("OCI_STACK_ID"),
               "--sort-by", "TIMECREATED", "--sort-order", "DESC",
               "--limit", "10").get("data") or []


def q_job_log() -> int:
    job_id = (os.environ.get("JOB_ID") or "latest").strip()
    if job_id in LATEST:
        # stack output shortens OCIDs for the public log, so "latest…" is how a job is named
        op = LATEST[job_id]
        jobs = [j for j in stack_jobs() if op is None or j.get("operation") == op]
        if not jobs:
            raise OciError(f"no {job_id.removeprefix('latest-') if op else ''} job on the stack")
        job = jobs[0]
        say(f"job         {job.get('operation')} {job.get('lifecycle-state')}  "
            f"{(job.get('time-created') or '?')[:16]}  {job.get('id')}")
        job_id = job["id"]
    if not JOB_ID.match(job_id):
        raise OciError("JOB_ID must be latest, latest-apply, latest-plan or a job OCID")
    text = oci("resource-manager", "job", "get-job-logs-content", "--job-id", job_id).get("data")
    lines = (text or "").splitlines()
    summary = [m[0] for line in lines if (m := SUMMARY_LINE.search(line))]
    for line in summary[-5:]:
        say(f"summary     {line}")
    say(f"log         last {min(len(lines), 300)} of {len(lines)} lines:")
    for line in lines[-300:]:
        say(f"  {line}")
    return 0


READ_EVENT = re.compile(r"^(Get|List|Summarize|Search|Request|Retrieve|Head|Validate)[A-Z]")
AUDIT_SHOWN = 100


def audit_events(hours: int) -> list[dict]:
    end = datetime.now(UTC).replace(second=0, microsecond=0)
    start = end - timedelta(hours=hours)
    data = oci("audit", "event", "list", "--compartment-id", compartment(), "--all",
               "--start-time", start.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ")).get("data") or []
    writes = []
    for ev in data:
        d = ev.get("data") or {}
        action = ((d.get("request") or {}).get("action") or "").upper()
        if action in ("GET", "HEAD", "OPTIONS"):
            continue  # reads, including this script's own
        if READ_EVENT.match(d.get("event-name") or ""):
            continue  # reads sent as POST (metric queries from the console, searches)
        writes.append(ev)
    writes.sort(key=lambda e: e.get("event-time") or "")
    return writes


def audit_report() -> list[str]:
    hours = int(os.environ.get("AUDIT_HOURS") or 24)
    hours = max(1, min(hours, 24 * 14))
    events = audit_events(hours)
    if len(events) > AUDIT_SHOWN:
        say(f"audit       showing the newest {AUDIT_SHOWN} of {len(events)}")
    for ev in events[-AUDIT_SHOWN:]:
        d = ev.get("data") or {}
        ident = d.get("identity") or {}
        status = str((d.get("response") or {}).get("status") or "-")
        say(f"audit       {str(ev.get('event-time') or '?')[:16]}  "
            f"{str(d.get('event-name') or '?'):<28} "
            f"{status:<4} by {ident.get('principal-name') or '?'} "
            f"from {ident.get('ip-address') or '?'}  on {d.get('resource-name') or '-'}")
    say(f"audit       {len(events)} write operation(s) in the last {hours} h")
    return []


def q_audit() -> int:
    audit_report()
    return 0


def cloud_guard_report() -> list[str]:
    data = oci("cloud-guard", "problem", "list", "--compartment-id", compartment(),
               "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE",
               "--lifecycle-state", "ACTIVE", "--all").get("data") or {}
    items = data.get("items") if isinstance(data, dict) else data
    problems = []
    for p in items or []:
        if p.get("lifecycle-detail") not in (None, "OPEN"):
            continue
        say(f"cloud-guard {(p.get('risk-level') or '?'):<8} {(p.get('detector-rule-id') or '?')}  "
            f"on {(p.get('resource-type') or '?')} {(p.get('resource-name') or '?')}  "
            f"last {str(p.get('time-last-detected') or '?')[:16]}")
        if p.get("risk-level") in ("CRITICAL", "HIGH"):
            problems.append(f"Cloud Guard {p.get('risk-level')}: {p.get('detector-rule-id')}")
    if not items:
        say("cloud-guard no open problems")
    return problems


def q_cloud_guard() -> int:
    cloud_guard_report()
    return 0


def q_budget() -> int:
    data = oci("budgets", "budget", "budget", "list", "--compartment-id", compartment(),
               "--target-type", "ALL", "--all").get("data") or []
    for b in data:
        say(f"budget      {b.get('display-name')}: spent {b.get('actual-spend')} of "
            f"{b.get('amount')} ({b.get('reset-period')}), forecast {b.get('forecasted-spend')}")
    if not data:
        say("budget      none set (docs/oracle-vm.md suggests a $1 alert on Pay As You Go)")
    return 0


def q_backups() -> int:
    data = oci("bv", "boot-volume-backup", "list", "--compartment-id", compartment(),
               "--all").get("data") or []
    for b in sorted(data, key=lambda b: (b.get("time-created") or ""), reverse=True)[:10]:
        say(f"backup      {(b.get('time-created') or '?')[:16]}  "
            f"{b.get('lifecycle-state') or '?':<10} "
            f"{(b.get('type') or '?'):<11} {b.get('display-name')}")
    if not data:
        say("backup      no boot volume backups")
    return 0


# ---------------------------------------------------------------- check

def expectations() -> dict[str, str]:
    e = os.environ
    return {
        "shape": e.get("EXPECT_SHAPE") or "VM.Standard.A1.Flex",
        "ocpus": e.get("EXPECT_OCPUS") or "2",
        "memory": e.get("EXPECT_MEMORY_GB") or "12",
        "os": e.get("EXPECT_OS") or "Canonical Ubuntu",
        "os_version": e.get("EXPECT_OS_VERSION") or "24.04",
        "ssh_fp": e.get("EXPECT_SSH_FP") or "",
        "public_ip": (e.get("EXPECT_PUBLIC_IP") or "any").lower(),     # yes | no | any
        "cloud_init": (e.get("EXPECT_CLOUD_INIT") or "any").lower(),   # yes | no | any
    }


def _num(value) -> str:
    try:
        return f"{float(value):g}"
    except (TypeError, ValueError):
        return str(value)


def check_report() -> list[str]:
    """Print the VM's key facts, mark each one that differs from expectations, return them."""
    want = expectations()
    inst = require_instance()
    bad: list[str] = []

    def line(label: str, value: str, problem: str | None = None) -> None:
        say(f"{label:<11} {value}" + (f"  ← {problem}" if problem else ""))
        if problem:
            bad.append(f"{label}: {problem}")

    cfg = inst.get("shape-config") or {}
    line("state", str(inst.get("lifecycle-state")),
         None if inst.get("lifecycle-state") == "RUNNING" else "expected RUNNING")
    shape_problem = []
    if inst.get("shape") != want["shape"]:
        shape_problem.append(f"shape {want['shape']}")
    if _num(cfg.get("ocpus")) != _num(want["ocpus"]):
        shape_problem.append(f"{want['ocpus']} OCPUs")
    if _num(cfg.get("memory-in-gbs")) != _num(want["memory"]):
        shape_problem.append(f"{want['memory']} GB")
    line("shape", f"{inst.get('shape')}  ocpus={_num(cfg.get('ocpus'))}  "
         f"memory_gb={_num(cfg.get('memory-in-gbs'))}",
         "expected " + ", ".join(shape_problem) if shape_problem else None)

    img = image_of(inst)
    os_ok = (img.get("operating-system") == want["os"]
             and str(img.get("operating-system-version") or "").startswith(want["os_version"]))
    line("image", f"{(img.get('display-name') or '?')}",
         None if os_ok else f"expected {want['os']} {want['os_version']}")

    publics = [v.get("public-ip") for v in vnics_of(inst) if v.get("public-ip")]
    pub_problem = None
    if want["public_ip"] == "yes" and not publics:
        pub_problem = "expected a public IP (cloud-init needs a route out)"
    elif want["public_ip"] == "no" and publics:
        pub_problem = "expected no public IP after the Tailscale lockdown"
    line("public ip", ", ".join(publics) if publics else "none", pub_problem)

    fps = ssh_fingerprints(metadata(inst).get("ssh_authorized_keys") or "")
    fp_problem = None
    if want["ssh_fp"] and not any(fp.startswith(want["ssh_fp"]) for fp in fps):
        fp_problem = f"expected {want['ssh_fp']}"
    line("ssh-key", ", ".join(fps) if fps else "none", fp_problem)

    ci = cloud_init_facts(inst)
    ci_problem = None
    if ci["set"] and ci.get("placeholder"):
        ci_problem = "the Tailscale key placeholder was never replaced"
    elif want["cloud_init"] == "yes" and not ci["set"]:
        ci_problem = "expected cloud-init (Tailscale is never installed without it)"
    desc = "not set" if not ci["set"] else f"set, {(ci.get('bytes') or '?')} bytes"
    line("cloud-init", desc, ci_problem)
    return bad


def q_check() -> int:
    bad = check_report()
    say()
    say("check       OK" if not bad else f"check       {len(bad)} mismatch(es)")
    return 1 if bad else 0


def q_watch() -> int:
    """The scheduled run. A missing VM is a notice, not a failure."""
    problems: list[str] = []
    try:
        problems += check_report()
        say()
        problems += metric_report()
    except NoInstance as e:
        say(f"watch       no instance named {e} yet; skipping the VM checks")
    say()
    for section, report in (("audit", audit_report), ("cloud-guard", cloud_guard_report)):
        try:
            problems += report()
        except OciError as e:
            if section == "cloud-guard" and "404" in str(e):
                say("cloud-guard not enabled in this tenancy (Identity & Security → Cloud Guard)")
            else:
                say(f"{section:<11} error: {explain(section, e)}")
                problems.append(f"{section} query failed")
        say()
    for p in problems:
        say(f"problem     {p}")
    say("watch       OK" if not problems else f"watch       {len(problems)} problem(s)")
    return 1 if problems else 0


QUERIES: dict[str, Callable[[], int]] = {
    "check": q_check, "instance": q_instance, "image": q_image, "network": q_network,
    "ssh-key": q_ssh_key, "cloud-init": q_cloud_init, "agent": q_agent, "metrics": q_metrics,
    "limits": q_limits, "stack": q_stack, "job-log": q_job_log, "audit": q_audit,
    "cloud-guard": q_cloud_guard, "budget": q_budget, "backups": q_backups, "watch": q_watch,
}
ALL = ["instance", "image", "network", "ssh-key", "cloud-init", "agent", "metrics", "limits",
       "stack", "audit", "cloud-guard", "budget", "backups"]


def service_error(text: str) -> str | None:
    """`code: message` from the CLI's multi-line `ServiceError: {json}` output."""
    start = text.find("{", text.find("ServiceError"))
    if "ServiceError" not in text or start < 0:
        return None
    try:
        body, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    return f"{body.get('code', '?')} ({body.get('status', '?')}): {body.get('message', '')}"


def explain(name: str, err: Exception) -> str:
    text = str(err)
    parsed = service_error(text)
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("Warning:")]
    first = (parsed or next((ln for ln in lines if "Error" in ln or "code" in ln), None)
             or (lines[0] if lines else text))[:300]
    if name == "cloud-guard" and "404" in text:
        return (f"{first}  (Cloud Guard is probably not enabled: Identity & Security → Cloud "
                f"Guard → Enable. If it is, the policy needs: read cloud-guard-family)")
    if "NotAuthorizedOrNotFound" in text or '"status": 404' in text:
        hint = POLICY.get(name)
        if hint:
            return f"{first}  (the inspector's policy needs: Allow group … to {hint} in tenancy)"
    return first


def run(name: str) -> int:
    try:
        return QUERIES[name]()
    except NoInstance as e:
        say(f"{name:<11} no instance named {e} (terminated, or not created yet)")
        return 2
    except (OciError, json.JSONDecodeError, KeyError) as e:
        say(f"{name:<11} error: {explain(name, e)}")
        return 2


def main(argv: list[str]) -> int:
    name = argv[1] if len(argv) > 1 else "check"
    if name not in QUERIES and name != "all":
        say(f"unknown query {name!r}; choose one of: {', '.join([*QUERIES, 'all'])}")
        return 2
    if name == "all":
        codes = []
        for q in ALL:
            say(f"== {q}")
            codes.append(run(q))
        code = max(codes)
    else:
        code = run(name)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### oracle-inspect: {name}\n\n```\n" + "\n".join(_out) + "\n```\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
