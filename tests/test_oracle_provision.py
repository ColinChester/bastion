"""scripts/oracle-provision.sh, run against a fake `oci` for each outcome the workflow
acts on. The workflow disables itself on `provisioned` and `config`, so a wrong
classification would either stop retrying too early or never stop."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "oracle-provision.sh"
LOOP = SCRIPT.with_name("oracle-provision-loop.sh")

FAKE = r'''#!/usr/bin/env bash
# Fake oci: behaviour chosen by files in $FAKE_DIR.
echo "$*" >> "$FAKE_DIR/calls"
case "$1 $2 $3" in
  "compute instance list")
    [ -f "$FAKE_DIR/list_error" ] && { cat "$FAKE_DIR/list_error" >&2; exit 1; }
    n=$(cat "$FAKE_DIR/list_count" 2>/dev/null || echo 0)
    [ -f "$FAKE_DIR/created" ] && n=1
    [ "$n" = 0 ] && exit 0
    echo '{"data":[{"lifecycle-state":"TERMINATED"},{"lifecycle-state":"RUNNING"}]}' ;;
  "resource-manager job create-apply-job")
    [ -f "$FAKE_DIR/create_error" ] && { cat "$FAKE_DIR/create_error" >&2; exit 1; }
    echo '{"data":{"id":"ocid1.ormjob.test"}}' ;;
  "resource-manager job get")
    if [[ "$*" == *failure-details* ]]; then cat "$FAKE_DIR/why" 2>/dev/null; exit 0; fi
    state=$(cat "$FAKE_DIR/state")
    [ "$state" = SUCCEEDED ] && [ -f "$FAKE_DIR/creates" ] && touch "$FAKE_DIR/created"
    echo "$state" ;;
  "resource-manager job get-job-logs-content")
    printf '{"data": "%s"}\n' "$(cat "$FAKE_DIR/logs" 2>/dev/null)" ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
'''


@pytest.fixture
def run(tmp_path):
    if not shutil.which("jq"):
        pytest.skip("jq not installed")
    fake = tmp_path / "oci"
    fake.write_text(FAKE)
    fake.chmod(0o755)

    def go(script=SCRIPT, extra_env=None, **files) -> tuple[dict, str]:
        for name, text in files.items():
            (tmp_path / name).write_text(text)
        out = tmp_path / "out"
        out.write_text("")
        env = {**os.environ, "OCI": str(fake), "FAKE_DIR": str(tmp_path),
               "OCI_STACK_ID": "ocid1.ormstack.test", "OCI_COMPARTMENT_ID": "ocid1.c",
               "POLL_SECONDS": "0", "MAX_POLLS": "3", "GITHUB_OUTPUT": str(out),
               **(extra_env or {})}
        proc = subprocess.run(["bash", str(script)], env=env, capture_output=True,
                              text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        result = dict(line.split("=", 1) for line in out.read_text().splitlines())
        calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
        return result, calls

    return go


def test_already_exists_stops_without_applying(run):
    result, calls = run(list_count="1")
    assert result["result"] == "provisioned"
    assert "create-apply-job" not in calls


def test_out_of_capacity_retries_quietly(run):
    result, _ = run(state="FAILED", why="Error Message: 500-InternalError, Out of host capacity.")
    assert result["result"] == "capacity"
    assert "capacity" in result["detail"]


def test_capacity_found_only_in_the_logs(run):
    result, _ = run(state="FAILED",
                    why="The job failed due to an error in the Terraform configuration.",
                    logs="Error: 500-InternalError, Out of host capacity.")
    assert result["result"] == "capacity"
    assert "Out of host capacity" in result["detail"]   # not the generic Terraform line


def test_rate_limit_counts_as_retry(run):
    result, _ = run(create_error='ServiceError: {"code": "TooManyRequests", "status": 429}')
    assert result["result"] == "capacity"


def test_success_is_confirmed_by_the_instance_list(run):
    result, _ = run(state="SUCCEEDED", creates="")
    assert result["result"] == "provisioned"


def test_success_without_an_instance_of_that_name_is_a_setup_problem(run):
    result, _ = run(state="SUCCEEDED")
    assert result["result"] == "config"
    assert "OCI_INSTANCE_NAME" in result["detail"]


@pytest.mark.parametrize("error", [
    'ServiceError: {"code": "NotAuthorizedOrNotFound", "status": 404}',
    'ServiceError: {"code": "LimitExceeded", "status": 400}',
    "ConfigFileNotFound: Could not find config file at /root/.oci/config",
    "ValueError: Must supply either a region or an endpoint.",
])
def test_setup_problems_stop_retrying(run, error):
    result, _ = run(create_error=error)
    assert result["result"] == "config"


def test_auth_failure_while_listing(run):
    result, _ = run(list_error='ServiceError: {"code": "NotAuthenticated", "status": 401}')
    assert result["result"] == "config"


def test_unknown_failure_keeps_trying(run):
    result, _ = run(state="FAILED", why="Error: something odd happened")
    assert result["result"] == "error"


def test_job_that_never_finishes(run):
    result, _ = run(state="IN_PROGRESS")
    assert result["result"] == "error"
    assert "still running" in result["detail"]


def test_loop_keeps_trying_through_capacity_errors(run):
    result, calls = run(script=LOOP, extra_env={"RETRY_EVERY": "0", "RETRY_FOR": "1"},
                        state="FAILED", why="Out of host capacity.")
    assert result["result"] == "capacity"
    assert calls.count("create-apply-job") == int(result["attempts"]) >= 1


def test_loop_stops_as_soon_as_the_vm_exists(run, tmp_path):
    result, calls = run(script=LOOP, extra_env={"RETRY_EVERY": "0", "RETRY_FOR": "600"},
                        state="SUCCEEDED", creates="")
    assert result["result"] == "provisioned" and result["attempts"] == "1"
    assert calls.count("create-apply-job") == 1


def test_loop_stops_on_a_setup_problem(run):
    result, _ = run(script=LOOP, extra_env={"RETRY_EVERY": "0", "RETRY_FOR": "600"},
                    create_error='ServiceError: {"code": "NotAuthorizedOrNotFound"}')
    assert result["result"] == "config" and result["attempts"] == "1"
