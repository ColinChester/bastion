"""scripts/oracle-inspect.py against a fake `oci`. Its output goes to public Actions logs, so
the redaction tests matter as much as the checks: no key, user_data, full OCID, public IP or
email may reach stdout."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "oracle-inspect.py"
spec = importlib.util.spec_from_file_location("oracle_inspect", SCRIPT)
inspect_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspect_mod)

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
args = sys.argv[1:]
with open(os.path.join(d, "calls"), "a") as f:
    f.write(" ".join(args) + "\n")
for prefix, resp in json.load(open(os.path.join(d, "responses.json"))):
    if args[:len(prefix)] == prefix:
        if "stderr" in resp:
            sys.stderr.write(resp["stderr"]); sys.exit(resp.get("code", 1))
        print(json.dumps(resp["stdout"])); sys.exit(0)
sys.stderr.write("unexpected: " + " ".join(args)); sys.exit(2)
'''

# A real-looking ed25519 public key (random bytes, not anyone's key).
KEY_BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes(range(32))).decode()
PUBKEY = f"ssh-ed25519 {KEY_BLOB} bastion-vm"
FP = "SHA256:" + base64.b64encode(
    hashlib.sha256(base64.b64decode(KEY_BLOB)).digest()).decode().rstrip("=")
TSKEY = "tskey-auth-kAbCdEf123CNTRL-SecretSecretSecret"
CLOUD_INIT = f"#cloud-config\nruncmd:\n  - tailscale up --authkey={TSKEY} --ssh\n"
INST_ID = "ocid1.instance.oc1.iad.anuwcljtexampleexampleexampleexampleexampleexampleqq7b6ja"
TENANCY = "ocid1.tenancy.oc1..aaaaaaaaexampleexampleexampleexampleexampleexampleexample2yq"
PUBLIC_IP = "203.0.113.45"


def instance(**over):
    inst = {
        "id": INST_ID, "display-name": "bastion-vm", "lifecycle-state": "RUNNING",
        "time-created": "2026-11-22T01:10:00.000Z", "availability-domain": "IgAY:US-ASHBURN-AD-1",
        "shape": "VM.Standard.A1.Flex", "shape-config": {"ocpus": 2.0, "memory-in-gbs": 12.0},
        "source-details": {"image-id": "ocid1.image.oc1.iad.aaaaubuntu2404arm",
                           "boot-volume-size-in-gbs": 100},
        "metadata": {"ssh_authorized_keys": PUBKEY,
                     "user_data": base64.b64encode(CLOUD_INIT.encode()).decode()},
    }
    inst.update(over)
    return inst


UBUNTU = {"display-name": "Canonical-Ubuntu-24.04-aarch64-2026.10.30-0",
          "operating-system": "Canonical Ubuntu", "operating-system-version": "24.04"}
ORACLE_LINUX = {"display-name": "Oracle-Linux-9.6-aarch64-2026.10.01-0",
                "operating-system": "Oracle Linux", "operating-system-version": "9"}


def responses(inst=None, image=UBUNTU, public_ip=PUBLIC_IP, extra=()):
    insts = [inst] if inst else []
    return [
        *extra,
        [["compute", "instance", "list"],
         {"stdout": {"data": [{"lifecycle-state": "TERMINATED", "time-created": "2026-11-13"},
                              *insts]}}],
        [["compute", "image", "get"], {"stdout": {"data": image}}],
        [["compute", "instance", "list-vnics"],
         {"stdout": {"data": [{"private-ip": "10.0.0.12", "public-ip": public_ip,
                               "subnet-id": "ocid1.subnet.oc1.iad.aaaasubnet"}]}}],
        [["network", "subnet", "get"],
         {"stdout": {"data": {"security-list-ids": ["ocid1.securitylist.oc1.iad.aaaasl"]}}}],
        [["network", "security-list", "get"],
         {"stdout": {"data": {"ingress-security-rules": [
             {"protocol": "6", "source": "0.0.0.0/0",
              "tcp-options": {"destination-port-range": {"min": 22, "max": 22}}}]}}}],
    ]


@pytest.fixture
def run(tmp_path):
    fake = tmp_path / "oci"
    fake.write_text(FAKE.replace("/usr/bin/env python3", sys.executable, 1))
    fake.chmod(0o755)

    def go(query, resp, **env):
        (tmp_path / "responses.json").write_text(json.dumps(resp))
        full_env = {**os.environ, "OCI": str(fake), "FAKE_DIR": str(tmp_path),
                    "OCI_COMPARTMENT_ID": TENANCY, **env}
        full_env.pop("GITHUB_STEP_SUMMARY", None)
        proc = subprocess.run([sys.executable, str(SCRIPT), query], env=full_env,
                              capture_output=True, text=True, timeout=60)
        calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
        return proc.returncode, proc.stdout, calls

    return go


def assert_public_safe(out: str):
    assert TSKEY not in out and "tskey-auth" not in out
    assert KEY_BLOB not in out
    assert INST_ID not in out and TENANCY not in out
    assert PUBLIC_IP not in out
    assert base64.b64encode(CLOUD_INIT.encode()).decode() not in out


# ---------------------------------------------------------------- check

def test_check_passes_for_the_intended_vm(run):
    code, out, _ = run("check", responses(instance()), EXPECT_SSH_FP=FP)
    assert code == 0, out
    assert "check       OK" in out
    assert FP in out
    assert_public_safe(out)


def test_check_flags_every_problem_the_nov_13_vm_had(run):
    """The first VM: Oracle Linux, 1 OCPU / 6 GB, no public IP, other key, no cloud-init."""
    other_key = "ssh-ed25519 " + base64.b64encode(b"\x00" * 51).decode() + " bastion-vm"
    bad = instance(**{"shape-config": {"ocpus": 1.0, "memory-in-gbs": 6.0},
                      "metadata": {"ssh_authorized_keys": other_key}})
    code, out, _ = run("check", responses(bad, image=ORACLE_LINUX, public_ip=None),
                       EXPECT_SSH_FP=FP, EXPECT_PUBLIC_IP="yes", EXPECT_CLOUD_INIT="yes")
    assert code == 1
    for marker in ("expected 2 OCPUs, 12 GB", "expected Canonical Ubuntu 24.04",
                   "expected a public IP", f"expected {FP}", "expected cloud-init"):
        assert marker in out, marker
    assert "5 mismatch(es)" in out


def test_check_catches_an_unreplaced_tailscale_placeholder(run):
    inst = instance(metadata={"ssh_authorized_keys": PUBKEY, "user_data": base64.b64encode(
        b"#cloud-config\nruncmd:\n  - tailscale up --authkey=__TAILSCALE_AUTHKEY__\n").decode()})
    code, out, _ = run("check", responses(inst))
    assert code == 1 and "placeholder was never replaced" in out


def test_check_after_lockdown_wants_no_public_ip(run):
    code, out, _ = run("check", responses(instance()), EXPECT_PUBLIC_IP="no")
    assert code == 1 and "expected no public IP" in out


def test_missing_vm_is_an_error_for_check(run):
    code, out, _ = run("check", responses(None))
    assert code == 2 and "no instance named bastion-vm" in out


# ---------------------------------------------------------------- single queries

def test_cloud_init_reports_hash_not_contents(run):
    code, out, _ = run("cloud-init", responses(instance()))
    assert code == 0
    assert hashlib.sha256(CLOUD_INIT.encode()).hexdigest() in out
    assert "tailscale key=yes" in out and "placeholder left=no" in out
    assert_public_safe(out)


def test_network_masks_the_public_ip_and_lists_ingress(run):
    code, out, _ = run("network", responses(instance()))
    assert code == 0
    assert "public=203.0.x.x" in out and "private=10.0.0.12" in out
    assert "tcp 22 from 0.0.0.0/0" in out
    assert_public_safe(out)


def test_metrics_flags_an_idle_vm(run):
    idle = {"data": [{"aggregated-datapoints": [{"value": v} for v in [1.0] * 100]}]}
    busy = {"data": [{"aggregated-datapoints": [{"value": v} for v in [35.0] * 100]}]}
    extra = [
        [["monitoring", "metric-data", "summarize-metrics-data", "--compartment-id", TENANCY,
          "--namespace", "oci_computeagent", "--query-text",
          f'CpuUtilization[5m]{{resourceId = "{INST_ID}"}}.mean()'], {"stdout": idle}],
        [["monitoring", "metric-data", "summarize-metrics-data", "--compartment-id", TENANCY,
          "--namespace", "oci_computeagent", "--query-text",
          f'MemoryUtilization[5m]{{resourceId = "{INST_ID}"}}.mean()'], {"stdout": busy}],
        [["monitoring", "metric-data"], {"stdout": {"data": []}}],
    ]
    code, out, _ = run("metrics", responses(instance(), extra=extra))
    assert code == 0
    assert "cpu     p95 7d:   1.0%  ← under the 20% reclaim line" in out
    assert "memory  p95 7d:  35.0%" in out and "memory  p95 7d:  35.0%  ←" not in out


def test_audit_shows_writes_only_and_masks_people(run):
    events = {"data": [
        {"event-time": "2026-11-22T01:00:00Z", "data": {
            "event-name": "GetInstance", "request": {"action": "GET"},
            "identity": {"principal-name": "bastion-inspector"}}},
        {"event-time": "2026-11-22T00:55:00Z", "data": {
            "event-name": "TerminateInstance", "request": {"action": "DELETE"},
            "response": {"status": "204"}, "resource-name": "bastion-vm",
            "identity": {"principal-name": "colin@example.com", "ip-address": "98.76.54.32"}}},
    ]}
    code, out, _ = run("audit", [[["audit", "event", "list"], {"stdout": events}]])
    assert code == 0
    assert "TerminateInstance" in out and "GetInstance" not in out
    assert "…@example.com" in out and "colin@" not in out
    assert "98.76.x.x" in out and "98.76.54.32" not in out
    assert "1 write operation(s) in the last 24 h" in out


def test_job_log_rejects_anything_but_a_job_ocid(run):
    code, out, calls = run("job-log", [], JOB_ID="ocid1.ormjob.oc1; rm -rf /")
    assert code == 2 and "must be a Resource Manager job OCID" in out
    assert calls == ""


def test_job_log_is_redacted_and_summarised(run):
    log = "\n".join([
        "Terraform will perform the following actions:",
        '  + metadata = {',
        f'      + "ssh_authorized_keys" = "{PUBKEY}"',
        f'      + "user_data"           = "{base64.b64encode(CLOUD_INIT.encode()).decode()}"',
        "    }",
        f"  + compartment_id = \"{TENANCY}\"",
        "Plan: 1 to add, 0 to change, 0 to destroy.",
    ])
    code, out, _ = run("job-log", [[["resource-manager", "job", "get-job-logs-content"],
                                    {"stdout": {"data": log}}]],
                       JOB_ID="ocid1.ormjob.oc1.iad.amaaaajob123")
    assert code == 0
    assert "summary     Plan: 1 to add, 0 to change, 0 to destroy." in out
    assert '"user_data"           = "<redacted>"' in out
    assert_public_safe(out)


def test_missing_policy_gets_a_hint(run):
    resp = [[["cloud-guard"], {"stderr": 'ServiceError: {"code": "NotAuthorizedOrNotFound", '
                                         '"status": 404}'}]]
    code, out, _ = run("cloud-guard", resp)
    assert code == 2 and "read cloud-guard-family" in out


def test_unknown_query_runs_nothing(run):
    code, out, calls = run("compute instance terminate", [])
    assert code == 2 and "unknown query" in out and calls == ""


def test_only_read_operations_are_ever_called(run):
    """Every oci call the script can make is a get/list/summarize: run them all and look."""
    extra = [[["instance-agent"], {"stdout": {"data": []}}],
             [["monitoring"], {"stdout": {"data": []}}],
             [["limits"], {"stdout": {"data": {"used": 2, "available": 2}}}],
             [["resource-manager"], {"stdout": {"data": []}}],
             [["audit"], {"stdout": {"data": []}}],
             [["cloud-guard"], {"stdout": {"data": {"items": []}}}],
             [["budgets"], {"stdout": {"data": []}}],
             [["bv"], {"stdout": {"data": []}}]]
    code, out, calls = run("all", responses(instance(), extra=extra),
                           OCI_STACK_ID="ocid1.ormstack.x")
    assert code == 0, out
    verbs = {line.split()[2] if line.startswith(("compute", "network", "resource-manager",
                                                 "instance-agent", "audit", "cloud-guard",
                                                 "budgets", "bv", "monitoring", "limits"))
             else line for line in calls.splitlines()}
    allowed = {"list", "get", "list-vnics", "summarize-metrics-data"}
    assert verbs <= allowed, verbs - allowed


# ---------------------------------------------------------------- watch (scheduled)

def test_watch_without_a_vm_is_not_a_failure(run):
    resp = [*responses(None),
            [["audit"], {"stdout": {"data": []}}],
            [["cloud-guard"], {"stdout": {"data": {"items": []}}}]]
    code, out, _ = run("watch", resp)
    assert code == 0, out
    assert "skipping the VM checks" in out and "watch       OK" in out


def test_watch_fails_on_a_high_cloud_guard_problem(run):
    problem = {"items": [{"risk-level": "HIGH", "detector-rule-id": "INSTANCE_HAS_PUBLIC_IP",
                          "resource-type": "Instance", "resource-name": "bastion-vm",
                          "lifecycle-detail": "OPEN"}]}
    resp = [*responses(None), [["audit"], {"stdout": {"data": []}}],
            [["cloud-guard"], {"stdout": {"data": problem}}]]
    code, out, _ = run("watch", resp)
    assert code == 1 and "Cloud Guard HIGH: INSTANCE_HAS_PUBLIC_IP" in out


# ---------------------------------------------------------------- redact() directly

@pytest.mark.parametrize("secret", [
    TSKEY,
    PUBKEY,
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
    "A" * 200,
])
def test_redact_removes_secrets(secret):
    assert secret not in inspect_mod.redact(f"before {secret} after")


def test_redact_shortens_ocids_with_dashes_in_the_region():
    ocid = ("ocid1.subnet.oc1.us-phoenix-1."
            "aaaaaaaaexampleexampleexampleexampleexampleexampleexgmdbea")
    assert inspect_mod.redact(ocid) == "ocid1.subnet…gmdbea"


def test_redact_keeps_private_ips_and_versions():
    text = "private 10.0.0.249 172.20.1.1 image Canonical-Ubuntu-24.04-aarch64-2026.10.30-0"
    assert inspect_mod.redact(text) == text


def test_fingerprint_matches_ssh_keygen_format():
    assert inspect_mod.ssh_fingerprints(PUBKEY) == [f"{FP} (ssh-ed25519)"]
