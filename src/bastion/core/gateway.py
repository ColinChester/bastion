"""The action gateway: the second key for anything that changes the Mac.

The orchestrator proposes; this separate service decides. It runs in its own container,
uses no model, and is the only holder of the Ed25519 key that bastiond's executor
accepts commands from. For each proposal it:

1. fetches the detection from bastiond itself (it doesn't trust the proposer's copy)
2. derives the target from that detection in code (`playbook.derive_args`)
3. evaluates the Cedar policy in `policy/` to choose: automatic, needs approval, or no
4. signs a short-lived command and sends it to the executor

If the policy, the detection lookup or bastiond is unavailable, nothing is sent.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path

import cedarpy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from bastion.core.edge import Edge, EdgeError
from bastion.core.playbook import CONTAIN_ACTIONS, FOLLOW_UP, derive_args

log = logging.getLogger(__name__)

COMMAND_TTL_MS = 120_000
TIER2 = tuple(FOLLOW_UP.values())


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")   # callers can never supply targets

    incident_id: str = Field(max_length=64)
    detection_id: int
    agent: str = Field(pattern="^(sentry|anchor|tide)$")
    action: str = Field(max_length=40)
    verdict: str = Field(pattern="^(malicious|suspicious|benign|inconclusive)$")
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(default="", max_length=300)


class FollowUp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(max_length=32)
    reason: str = Field(default="", max_length=300)


class Policy:
    def __init__(self, policy_dir: Path):
        files = sorted(Path(policy_dir).glob("*.cedar"))
        if not files:
            raise RuntimeError(f"no Cedar policies in {policy_dir}")
        self.text = "\n".join(f.read_text() for f in files)
        # cedarpy reports policies as policy0, policy1...; map them to their @id names.
        self.names = re.findall(r'@id\("([^"]+)"\)', self.text)
        # Fail at startup, not at the first incident, if the policy doesn't parse.
        probe = self.decide("sentry", "suspend_process", {"path": "/x"}, "benign", 0, "low")
        if probe[0] != "deny":
            raise RuntimeError("policy sanity check failed: a benign verdict was allowed")

    def _allowed(self, agent: str, action: str, resource: dict, context: dict
                 ) -> tuple[bool, list[str]]:
        entities = [
            {"uid": {"type": "Agent", "id": agent}, "attrs": {}, "parents": []},
            {"uid": {"type": "Target", "id": "target"}, "attrs": resource, "parents": []},
        ]
        result = cedarpy.is_authorized(
            {"principal": f'Agent::"{agent}"', "action": f'Action::"{action}"',
             "resource": 'Target::"target"', "context": context}, self.text, entities)
        if result.diagnostics.errors:
            log.error("policy errors: %s", result.diagnostics.errors)
            return False, [str(e) for e in result.diagnostics.errors]
        return result.allowed, [self._name(r) for r in result.diagnostics.reasons]

    def _name(self, policy_id: str) -> str:
        try:
            return self.names[int(str(policy_id).removeprefix("policy"))]
        except (ValueError, IndexError):
            return str(policy_id)

    def decide(self, agent: str, action: str, resource: dict, verdict: str,
               confidence: float, rule_severity: str) -> tuple[str, list[str]]:
        """("auto" | "approval" | "deny", ids of the policies that decided)."""
        ctx = {"verdict": verdict, "confidence": int(confidence * 100),
               "rule_severity": rule_severity or "medium", "human_approval": False}
        ok, why = self._allowed(agent, action, resource, ctx)
        if ok:
            return "auto", why
        ok2, why2 = self._allowed(agent, action, resource, {**ctx, "human_approval": True})
        return ("approval", why2) if ok2 else ("deny", why or why2)


class Gateway:
    def __init__(self, *, edge: Edge, policy: Policy, signing_key: Ed25519PrivateKey,
                 send_command):
        self.edge, self.policy, self.key, self.send = edge, policy, signing_key, send_command

    def _signed(self, action: str, args: dict, auto: bool, meta: dict) -> dict:
        now = int(time.time() * 1000)
        cmd = {"v": 1, "id": uuid.uuid4().hex, "issued_ms": now,
               "expires_ms": now + COMMAND_TTL_MS, "action": action, "args": args,
               "auto": auto, **meta}
        payload = json.dumps(cmd, sort_keys=True, separators=(",", ":"))
        return {"payload": payload,
                "sig": base64.b64encode(self.key.sign(payload.encode())).decode()}

    def propose(self, p: Proposal) -> dict:
        if p.action not in CONTAIN_ACTIONS:
            return {"status": "denied", "detail": f"{p.action} is not a containment action"}
        try:
            detection = self.edge.query("detection", det_id=p.detection_id)
        except EdgeError as exc:
            return {"status": "error", "detail": f"could not load the detection: {exc}"}
        if detection is None:
            return {"status": "denied", "detail": "unknown detection"}
        args = derive_args(p.action, detection)
        if args is None:
            return {"status": "denied",
                    "detail": f"the detection has no target for {p.action}"}
        resource = {"path": args.get("path", "")}
        decision, why = self.policy.decide(p.agent, p.action, resource, p.verdict,
                                           p.confidence, detection.get("severity", ""))
        base = {"action": p.action, "args": args, "policy": decision, "policy_ids": why}
        if decision == "deny":
            return {**base, "status": "denied", "detail": "policy does not allow this"}
        meta = {"incident_id": p.incident_id, "agent": p.agent, "reason": p.reason}
        result = self._send(p.action, args, decision == "auto", meta)
        out = {**base, **result}
        # After an automatic containment, offer the permanent step for approval.
        if result.get("status") == "executed" and p.action in FOLLOW_UP:
            follow = self.follow_up(FollowUp(action_id=result["action_id"],
                                             reason=f"finish: {p.reason}"[:300]),
                                    incident_id=p.incident_id)
            out["follow_up"] = {k: follow.get(k) for k in ("status", "approval_id", "action")}
        return out

    def follow_up(self, f: FollowUp, incident_id: str = "") -> dict:
        """Request permanent removal of something an executed containment holds."""
        try:
            actions = self.edge.exec_get("actions", limit=200)
        except EdgeError as exc:
            return {"status": "error", "detail": str(exc)}
        rec = next((a for a in actions if a["id"] == f.action_id), None)
        if rec is None or rec["status"] != "executed" or rec["action"] not in FOLLOW_UP:
            return {"status": "denied", "detail": "no active containment with that id"}
        action = FOLLOW_UP[rec["action"]]
        decision, why = self.policy.decide("warden", action, {}, "malicious", 1.0, "high")
        if decision != "approval":   # tier 2 must never come out as automatic
            return {"status": "denied", "detail": "policy does not allow this",
                    "policy_ids": why}
        meta = {"incident_id": incident_id or rec.get("incident_id", ""), "agent": "warden",
                "reason": f.reason}
        return {"action": action, "policy": decision, "policy_ids": why,
                **self._send(action, {"action_id": f.action_id}, False, meta)}

    def _send(self, action: str, args: dict, auto: bool, meta: dict) -> dict:
        try:
            return self.send(self._signed(action, args, auto, meta))
        except EdgeError as exc:   # fail closed: nothing ran
            return {"status": "error", "detail": f"executor unreachable: {exc}"}


def create_app(gateway: Gateway, token: str) -> FastAPI:
    app = FastAPI(title="Bastion gateway", docs_url=None, redoc_url=None, openapi_url=None)

    def auth(authorization: str | None) -> None:
        if not hmac.compare_digest((authorization or "").encode(),
                                   f"Bearer {token}".encode()):
            raise HTTPException(401, "unauthorized")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/propose")
    def propose(p: Proposal, authorization: str | None = Header(default=None)):
        auth(authorization)
        result = gateway.propose(p)
        log.info("proposal %s by %s on detection %s -> %s", p.action, p.agent,
                 p.detection_id, result.get("status"))
        return result

    @app.post("/follow-up")
    def follow_up(f: FollowUp, authorization: str | None = Header(default=None)):
        auth(authorization)
        return gateway.follow_up(f)

    return app


def app_from_env() -> FastAPI:
    from bastion.core.edge import EdgeClient

    key_b64 = os.environ.get("BASTION_GATEWAY_KEY", "")
    token = os.environ.get("BASTION_GATEWAY_TOKEN", "")
    if len(token) < 32 or not key_b64:
        raise SystemExit("BASTION_GATEWAY_KEY and BASTION_GATEWAY_TOKEN must be set "
                         "(run scripts/setup-phase3.sh)")
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64))
    edge = EdgeClient(os.environ.get("BASTION_EDGE_URL", "http://host.docker.internal:8765"),
                      os.environ.get("BASTION_EDGE_TOKEN", ""))
    policy = Policy(Path(os.environ.get("BASTION_POLICY_DIR", "policy")))
    gw = Gateway(edge=edge, policy=policy, signing_key=key,
                 send_command=lambda env: edge.exec_post("command", env))
    return create_app(gw, token)
