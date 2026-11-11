"""Phase 3 end to end: detection -> agents -> gateway (Cedar) -> signed command ->
executor, plus the console's passkey approval flow. Only the model and the operating
system calls are faked."""

from __future__ import annotations

import signal
from pathlib import Path

import httpx
import pytest
from conftest import exec_cols, oq
from fastapi.testclient import TestClient
from softpasskey import SoftPasskey
from test_core import decision_call, finding_call, standard_script
from test_executor import ORIGIN, RP, FakeSystem, Signer

from bastion.collectors import RawRecord
from bastion.core.corestore import CoreStore
from bastion.core.edge import LocalEdge
from bastion.core.gateway import Gateway, Policy, Proposal
from bastion.core.models import ScriptedClient
from bastion.core.playbook import derive_args
from bastion.core.push import Pusher
from bastion.core.settings import Settings
from bastion.core.web import create_app
from bastion.core.worker import Worker
from bastion.daemon import Pipeline
from bastion.edge_api import EdgeQueries
from bastion.executor.actions import ProcInfo
from bastion.executor.service import Executor
from bastion.executor.store import ExecStore
from bastion.store import Store

POLICY_DIR = Path(__file__).resolve().parents[1] / "policy"
PROPOSE = [{"action": "suspend_process", "target": "pid 1 /sbin/launchd", "reason": "stop"},
           {"action": "quarantine_file", "target": "/etc/hosts", "reason": "remove"}]


class DirectGateway:
    """What the worker and console see: the gateway's two calls, without HTTP."""

    def __init__(self, gw: Gateway):
        self.gw, self.down = gw, False

    def propose(self, body: dict) -> dict:
        if self.down:
            raise httpx.ConnectError("gateway down")
        return self.gw.propose(Proposal(**body))

    def follow_up(self, action_id: str, reason: str = "") -> dict:
        from bastion.core.gateway import FollowUp
        return self.gw.follow_up(FollowUp(action_id=action_id, reason=reason))


@pytest.fixture
def world(cfg, tmp_path):
    evil = tmp_path / "Users" / "colin" / "Downloads" / "evil"
    evil.parent.mkdir(parents=True)
    evil.write_bytes(b"\xcf\xfa\xed\xfe payload")
    signer = Signer()
    x = cfg.executor
    x.enabled, x.command_public_key, x.rp_id, x.origin = True, signer.public, RP, ORIGIN
    x.quarantine_roots = [str(tmp_path / "Users") + "/"]
    system = FakeSystem()
    system.procs[4000] = ProcInfo(4000, str(evil), "Wed Nov 11 12:00:00 2026")
    executor = Executor(cfg, ExecStore(":memory:"), system)

    store = Store(cfg.db_path)
    cols = exec_cols(str(evil), str(evil), pid=4000, flags="ADHOC")
    Pipeline(cfg, store).handle(RawRecord("osquery", oq("process_events", cols)))
    edge = LocalEdge(EdgeQueries(store))
    edge.executor = executor
    gw = Gateway(edge=edge, policy=Policy(POLICY_DIR), signing_key=signer.key,
                 send_command=lambda env: edge.exec_post("command", env))
    settings = Settings(data_dir=tmp_path, ntfy_url="http://ntfy.test", ntfy_topic="t",
                        console_url=ORIGIN)
    core = CoreStore(":memory:")
    core.set_state("triage_from_ms", "0")
    pushes = []

    def transport(request):
        pushes.append(request)
        return httpx.Response(200, json={})

    pusher = Pusher(settings, httpx.Client(transport=httpx.MockTransport(transport)))
    gateway = DirectGateway(gw)

    def run(verdict="malicious", confidence=0.9):
        script = standard_script(
            agent_final=finding_call(verdict, confidence, proposed_actions=PROPOSE),
            warden=decision_call(verdict, confidence=confidence))
        Worker(settings, core, edge, ScriptedClient(script), pusher, gateway).run_once()
        return core.get_incident(core.list_incidents()[0]["id"])

    return {"run": run, "executor": executor, "system": system, "evil": evil, "edge": edge,
            "gateway": gateway, "gw": gw, "pushes": pushes, "settings": settings,
            "core": core, "signer": signer}


def test_one_event_two_detections_one_action(world):
    """The test file sits under a temp folder, so two rules fire for the one event."""
    assert len(world["edge"].query("pending")) == 2
    world["executor"].set_mode("on")
    world["run"]()
    assert world["system"].signals == [(4000, signal.SIGSTOP)]
    assert len(world["executor"].list_actions()) == 2
    assert len(world["executor"].list_approvals()) == 1


def test_shadow_mode_logs_what_it_would_do(world):
    inc = world["run"]()
    assert [(r.action, r.status, r.policy) for r in inc.responses] == [
        ("suspend_process", "shadow", "auto"), ("quarantine_file", "shadow", "auto")]
    assert world["system"].signals == [] and world["evil"].exists()
    assert "would have" in world["pushes"][0].content.decode()
    assert "sentry-auto-contain" in inc.responses[0].policy_ids


def test_autonomy_on_contains_and_asks_before_deleting(world):
    world["executor"].set_mode("on")
    inc = world["run"]()
    assert [r.status for r in inc.responses] == ["executed", "executed"]
    assert world["system"].signals == [(4000, signal.SIGSTOP)]
    assert not world["evil"].exists()
    # the model's own "target" text (pid 1, /etc/hosts) was never used
    acts = {a["action"]: a for a in world["executor"].list_actions()}
    assert acts["suspend_process"]["args"] == {"pid": 4000, "path": str(world["evil"])}
    assert acts["quarantine_file"]["args"] == {"path": str(world["evil"])}
    # permanent deletion is offered, not done
    pending = world["executor"].list_approvals()
    assert [p["command"]["action"] for p in pending] == ["delete_quarantined"]
    assert inc.responses[1].follow_up_approval_id == pending[0]["id"]
    body = world["pushes"][0].content.decode()
    assert "Contained" in body and "/" not in body.replace("and/or", "")
    assert world["pushes"][0].headers["Click"].endswith("/approvals")
    # and it can be put back
    assert world["executor"].undo_local(acts["quarantine_file"]["id"])["status"] == "undone"
    assert world["evil"].exists()


def test_suspicious_verdict_asks_for_approval_instead_of_acting(world):
    world["executor"].set_mode("on")
    inc = world["run"]("suspicious", 0.7)
    assert [(r.status, r.policy) for r in inc.responses] == [
        ("pending_approval", "approval")] * 2
    assert world["system"].signals == [] and world["evil"].exists()
    assert "approve or deny" in world["pushes"][0].content.decode()


def test_gateway_down_means_nothing_happens(world):
    world["executor"].set_mode("on")
    world["gateway"].down = True
    inc = world["run"]()
    assert all(r.status == "error" for r in inc.responses)
    assert world["system"].signals == [] and world["evil"].exists()
    assert world["executor"].list_actions() == []


def test_policy_denies_wrong_domain_benign_and_unknown(world):
    det = world["edge"].query("pending")[0]["detection_id"]

    def propose(**kw):
        base = {"incident_id": "i", "detection_id": det, "agent": "sentry",
                "action": "suspend_process", "verdict": "malicious", "confidence": 0.95}
        return world["gw"].propose(Proposal(**{**base, **kw}))

    assert propose(agent="anchor")["status"] == "denied"
    assert propose(verdict="benign")["status"] == "denied"
    assert propose(action="delete_quarantined")["status"] == "denied"
    assert propose(action="disable_launch_item", agent="anchor")["status"] == "denied"
    assert propose(detection_id=987654)["status"] == "denied"
    assert world["executor"].list_actions() == []


def test_targets_come_only_from_the_detection():
    det = {"subject": {"process": {"pid": 7, "path": "/Users/c/Downloads/x"},
                       "file": {"path": "/Users/c/.ssh/id_ed25519"}}}
    assert derive_args("quarantine_file", det) == {"path": "/Users/c/Downloads/x"}
    assert derive_args("suspend_process", det) == {"pid": 7, "path": "/Users/c/Downloads/x"}
    assert derive_args("disable_launch_item", det) is None
    plist = {"subject": {"file": {"path": "/Users/c/Library/LaunchAgents/a.plist"}}}
    assert derive_args("disable_launch_item", plist) == {
        "path": "/Users/c/Library/LaunchAgents/a.plist"}
    assert derive_args("suspend_process", plist) is None


# ---- console --------------------------------------------------------------------------

@pytest.fixture
def console(world):
    app = create_app(world["settings"], world["core"], edge=world["edge"],
                     gateway=world["gateway"])
    return TestClient(app, base_url=ORIGIN)


def test_console_passkey_enroll_approve_and_undo(world, console):
    world["executor"].set_mode("on")
    world["run"]("suspicious", 0.7)
    page = console.get("/approvals")
    assert page.status_code == 200 and "Pause a program" in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert console.get("/static/passkey.js").status_code == 200

    key = SoftPasskey(RP, ORIGIN)
    code = world["executor"].new_enroll_code()
    start = console.post("/api/enroll/options", json={"code": code}).json()
    done = console.post("/api/enroll/verify", json={
        "code": code, "challenge_id": start["challenge_id"], "name": "phone",
        "credential": key.register(start["options"])})
    assert done.status_code == 200 and done.json()["registered"]

    approvals = {a["command"]["action"]: a["id"] for a in world["executor"].list_approvals()}
    aid = approvals["quarantine_file"]
    start = console.post(f"/api/approve/{aid}/options", json={}).json()
    result = console.post(f"/api/approve/{aid}/verify", json={
        "challenge_id": start["challenge_id"], "credential": key.sign(start["options"])})
    assert result.json()["status"] == "executed" and not world["evil"].exists()

    assert console.post(f"/api/deny/{approvals['suspend_process']}", json={}).json()[
        "status"] == "denied"
    action_id = result.json()["action_id"]
    asked = console.post(f"/api/request-delete/{action_id}", json={})
    assert asked.json()["status"] == "pending_approval"
    assert "Permanently delete a quarantined file" in console.get("/approvals").text

    start = console.post(f"/api/undo/{action_id}/options", json={}).json()
    undone = console.post(f"/api/undo/{action_id}/verify", json={
        "challenge_id": start["challenge_id"], "credential": key.sign(start["options"])})
    assert undone.json()["status"] == "undone" and world["evil"].exists()
    ok, _, _ = world["executor"].store.verify_audit()
    assert ok


def test_console_api_refuses_cross_site_and_bad_requests(world, console):
    world["run"]("suspicious", 0.7)
    aid = world["executor"].list_approvals()[0]["id"]
    evil = {"Origin": "https://evil.example"}
    assert console.post(f"/api/deny/{aid}", json={}, headers=evil).status_code == 403
    assert console.post(f"/api/deny/{aid}", json={},
                        headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert console.post(f"/api/deny/{aid}", content="x",
                        headers={"Content-Type": "text/plain"}).status_code == 415
    assert console.post("/api/deny/../../etc", json={}).status_code in (400, 404)
    assert console.post("/api/approve/zzzz/options", json={}).status_code == 400
    # approving without a registered passkey is refused by the executor
    r = console.post(f"/api/approve/{aid}/options", json={})
    assert r.status_code == 400 and "passkey" in r.json()["detail"]
    assert world["executor"].list_approvals()[0]["status"] == "pending"


def test_console_without_executor_explains(world):
    app = create_app(world["settings"], world["core"])
    client = TestClient(app, base_url=ORIGIN)
    assert "set up yet" in client.get("/approvals").text
    assert client.post("/api/deny/abcdef12", json={}).status_code == 503


# ---- over real HTTP, the gateway's own API, and the root CLI --------------------------

def _edge_server(cfg, signer):
    from bastion.edge_api import start_edge_api

    token = "t" * 40
    cfg.edge_api.enabled, cfg.edge_api.port, cfg.edge_api.token = True, 0, token
    x = cfg.executor
    x.enabled, x.command_public_key, x.rp_id, x.origin = True, signer.public, RP, ORIGIN
    Store(cfg.db_path)
    server = start_edge_api(cfg)
    return server, f"http://127.0.0.1:{server.server_address[1]}", token


def test_exec_routes_over_http(cfg):
    from bastion.core.edge import EdgeClient, EdgeError

    signer = Signer()
    server, url, token = _edge_server(cfg, signer)
    try:
        edge = EdgeClient(url, token)
        assert edge.exec_get("status")["mode"] == "shadow"
        env = signer.command("suspend_process", {"pid": 1, "path": "/sbin/launchd"})
        assert edge.exec_post("command", env)["status"] == "refused"   # protected program
        forged = {"payload": env["payload"].replace("launchd", "launchx"), "sig": env["sig"]}
        with pytest.raises(EdgeError, match="signature"):
            edge.exec_post("command", forged)
        with pytest.raises(EdgeError):
            edge.exec_post("shell", {"cmd": "id"})
        with pytest.raises(EdgeError):
            EdgeClient(url, "wrong" * 8).exec_get("status")
        big = httpx.post(f"{url}/v1/exec/command", content=b"x" * 70_000,
                         headers={"Authorization": f"Bearer {token}"})
        assert big.status_code == 413
        # the Phase 2 read API is still there and still read-only
        assert edge.query("pending") == []
    finally:
        server.shutdown()
        server.server_close()


def test_edge_has_no_exec_routes_when_executor_is_off(cfg):
    from bastion.core.edge import EdgeClient, EdgeError

    server, url, token = _edge_server(cfg, Signer())
    server.shutdown()
    server.server_close()
    cfg.executor.enabled = False
    from bastion.edge_api import start_edge_api
    server = start_edge_api(cfg)
    try:
        edge = EdgeClient(f"http://127.0.0.1:{server.server_address[1]}", token)
        with pytest.raises(EdgeError):
            edge.exec_get("status")
    finally:
        server.shutdown()
        server.server_close()


def test_gateway_http_needs_its_token(world):
    from bastion.core.gateway import create_app as gateway_app

    client = TestClient(gateway_app(world["gw"], "g" * 40))
    det = world["edge"].query("pending")[0]["detection_id"]
    body = {"incident_id": "i1", "detection_id": det, "agent": "sentry",
            "action": "suspend_process", "verdict": "malicious", "confidence": 0.9}
    assert client.get("/healthz").status_code == 200
    assert client.post("/propose", json=body).status_code == 401
    assert client.post("/propose", json=body,
                       headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = client.post("/propose", json=body, headers={"Authorization": "Bearer " + "g" * 40})
    assert ok.status_code == 200 and ok.json()["status"] == "shadow"
    extra = client.post("/propose", json={**body, "args": {"pid": 1}},
                        headers={"Authorization": "Bearer " + "g" * 40})
    assert extra.status_code == 422        # callers can't supply targets


def test_gateway_refuses_to_start_without_a_key(monkeypatch):
    from bastion.core.gateway import app_from_env

    for var in ("BASTION_GATEWAY_KEY", "BASTION_GATEWAY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SystemExit):
        app_from_env()


def test_root_cli_runs_the_switches(tmp_path, monkeypatch, capsys):
    import os

    from bastion import cli
    from bastion.config import load_config

    conf = tmp_path / "config.toml"
    conf.write_text(f'data_dir = "{tmp_path / "data"}"\n')
    base = ["--config", str(conf)]
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    with pytest.raises(SystemExit) as stop:
        cli.main([*base, "autonomy", "on"])
    assert "sudo" in str(stop.value)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    signer = Signer()
    assert cli.main([*base, "enable-executor", "--public-key", signer.public,
                     "--rp-id", RP, "--origin", ORIGIN]) == 0
    cfg = load_config(conf)
    assert cfg.executor.enabled and cfg.executor.command_public_key == signer.public
    assert cfg.data_dir == tmp_path / "data"

    assert cli.main([*base, "autonomy"]) == 0
    assert "shadow (log only)" in capsys.readouterr().out
    assert cli.main([*base, "autonomy", "on"]) == 1          # shadow period not over
    assert "shadow period" in capsys.readouterr().out
    assert cli.main([*base, "autonomy", "on", "--force"]) == 0
    assert cli.main([*base, "autonomy"]) == 0
    assert "ON" in capsys.readouterr().out
    assert cli.main([*base, "autonomy", "off"]) == 0

    assert cli.main([*base, "passkey", "enroll"]) == 0
    out = capsys.readouterr().out
    assert ORIGIN + "/enroll" in out
    assert cli.main([*base, "passkey", "list"]) == 0
    assert cli.main([*base, "approvals"]) == 0
    assert cli.main([*base, "actions"]) == 0
    assert cli.main([*base, "deny", "nope"]) == 1
    assert cli.main([*base, "audit", "--verify"]) == 0
    assert "intact" in capsys.readouterr().out


def test_worker_and_console_share_one_gateway_switch(monkeypatch, tmp_path):
    """Regression: `bastion-core run` once built its worker without the gateway, so
    nothing would ever have been proposed."""
    from bastion.core import cli as core_cli
    from bastion.core import worker as worker_mod

    assert core_cli._gateway(Settings(data_dir=tmp_path)) is None
    s = Settings(data_dir=tmp_path, edge_token="e" * 40, gateway_url="http://gateway:8788",
                 gateway_token="g" * 40)
    assert core_cli._gateway(s) is not None
    seen = {}

    class FakeWorker:
        def __init__(self, *a, gateway=None, **kw):
            seen["gateway"] = gateway

        def run_forever(self):
            return None

    monkeypatch.setattr(worker_mod, "Worker", FakeWorker)
    monkeypatch.setattr(core_cli, "_model", lambda: None)
    monkeypatch.setattr("bastion.core.tracing.setup_tracing", lambda: None)
    assert core_cli.cmd_run(None, s) == 0
    assert seen["gateway"] is not None


def test_doctor_reports_the_executor(cfg):
    from bastion.doctor import _executor_checks

    assert _executor_checks(cfg) == []
    cfg.executor.enabled, cfg.executor.command_public_key = True, Signer().public
    got = {h.component: h for h in _executor_checks(cfg)}
    assert "shadow mode, day 1" in got["executor"].detail
    assert got["passkey"].status == "warn" and "enroll" in got["passkey"].fix
    assert got["audit log"].status == "ok"
