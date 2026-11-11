"""The executor service: signed commands in, checked actions out.

Flow for one command from the gateway:

    verify signature, expiry and nonce  ->  validate arguments  ->  safety check
        tier 2, or not marked automatic  ->  stored as a pending approval (passkey needed)
        tier 1 automatic, shadow mode    ->  recorded as "would have done"
        tier 1 automatic, autonomy on    ->  rate limit  ->  execute  ->  undo record

An approval executes the request exactly as stored. The passkey signs a challenge
derived from that request's hash, so approving one thing can't authorize another.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bastion.config import Config
from bastion.executor.actions import TIERS, Actions, Failed, Refused, System, clean_args
from bastion.executor.store import ExecStore, canonical

log = logging.getLogger(__name__)

MAX_COMMAND_LIFETIME_MS = 10 * 60_000
CLOCK_SKEW_MS = 60_000
CHALLENGE_TTL_MS = 5 * 60_000
ENROLL_TTL_MS = 10 * 60_000
MODE_KEY = "autonomy"            # "shadow" (default) or "on"
SHADOW_START_KEY = "shadow_started_ms"


class Rejected(Exception):
    """The request itself is not acceptable (bad signature, replay, bad passkey...)."""


def action_hash(action: str, args: dict) -> str:
    return hashlib.sha256(canonical({"action": action, "args": args}).encode()).hexdigest()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _now() -> int:
    return int(time.time() * 1000)


class Executor:
    def __init__(self, cfg: Config, store: ExecStore | None = None,
                 system: System | None = None):
        self.cfg = cfg
        self.x = cfg.executor
        self.store = store or ExecStore(cfg.executor_db_path)
        self.actions = Actions(self.x, cfg.vault_dir, system)
        if self.store.get_state(SHADOW_START_KEY) is None:
            self.store.set_state(SHADOW_START_KEY, str(_now()))

    # ---- mode ---------------------------------------------------------------------
    def mode(self) -> str:
        return "on" if self.store.get_state(MODE_KEY) == "on" else "shadow"

    def shadow_day(self, now_ms: int | None = None) -> int:
        start = int(self.store.get_state(SHADOW_START_KEY) or _now())
        return ((now_ms or _now()) - start) // 86_400_000 + 1

    def set_mode(self, mode: str, by: str = "cli") -> None:
        if mode not in ("on", "shadow"):
            raise ValueError("mode must be 'on' or 'shadow'")
        self.store.set_state(MODE_KEY, mode)
        self.store.audit("mode_changed", {"mode": mode, "by": by})

    def status(self) -> dict:
        now = _now()
        self.store.expire_approvals(now)
        return {
            "enabled": self.x.enabled, "mode": self.mode(), "shadow_day": self.shadow_day(now),
            "shadow_days": self.x.shadow_days,
            "auto_actions_last_hour": self.store.count_auto_executed_since(now - 3_600_000),
            "max_auto_actions_per_hour": self.x.max_auto_actions_per_hour,
            "passkeys": len(self.store.list_passkeys()),
            "pending_approvals": len(self.store.list_approvals("pending")),
            "rp_id": self.x.rp_id,
        }

    # ---- commands -----------------------------------------------------------------
    def _verify_envelope(self, envelope: dict, now: int) -> dict:
        try:
            payload = envelope["payload"]
            sig = base64.b64decode(envelope["sig"], validate=True)
            key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(self.x.command_public_key, validate=True))
            key.verify(sig, payload.encode())
            cmd = json.loads(payload)
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            raise Rejected("bad command signature") from exc
        if not isinstance(cmd, dict) or cmd.get("v") != 1:
            raise Rejected("unsupported command version")
        issued, expires = cmd.get("issued_ms"), cmd.get("expires_ms")
        nonce = cmd.get("id")
        if not (isinstance(issued, int) and isinstance(expires, int)
                and isinstance(nonce, str) and 16 <= len(nonce) <= 64):
            raise Rejected("malformed command")
        if issued > now + CLOCK_SKEW_MS or expires <= now \
                or expires - issued > MAX_COMMAND_LIFETIME_MS:
            raise Rejected("command expired or not yet valid")
        if not self.store.use_nonce(nonce, expires + CLOCK_SKEW_MS, now):
            raise Rejected("command was already used (replay)")
        return cmd

    def handle_command(self, envelope: dict) -> dict:
        """Process one signed command. Returns a result dict; raises Rejected."""
        if not self.x.enabled:
            raise Rejected("executor is disabled")
        now = _now()
        cmd = self._verify_envelope(envelope, now)
        action = cmd.get("action", "")
        meta = {"incident_id": str(cmd.get("incident_id", ""))[:64],
                "agent": str(cmd.get("agent", ""))[:32],
                "reason": str(cmd.get("reason", ""))[:400]}
        try:
            args = clean_args(action, cmd.get("args"))
            self.actions.check(action, args, self.store)
        except Refused as exc:
            self.store.audit("command_refused", {"action": action, "why": str(exc), **meta})
            return {"status": "refused", "detail": str(exc)}
        tier = TIERS[action]
        auto = cmd.get("auto") is True and tier == 1  # tier 2 is never automatic
        request = {"action": action, "args": args, "tier": tier, **meta}

        if not auto:
            approval_id = uuid.uuid4().hex[:16]
            self.store.add_approval({
                "id": approval_id, "created_ms": now,
                "expires_ms": now + self.x.approval_ttl_hours * 3_600_000,
                "command": request, "action_hash": action_hash(action, args)})
            self.store.audit("approval_requested", {"approval_id": approval_id, **request})
            return {"status": "pending_approval", "approval_id": approval_id,
                    "detail": "waiting for a passkey approval"}

        action_id = uuid.uuid4().hex[:16]
        if self.mode() != "on":
            self.store.add_action({"id": action_id, "ts_ms": now, **request, "auto": True,
                                   "status": "shadow",
                                   "detail": "shadow mode: would have run, nothing changed"})
            self.store.audit("action_shadow", {"action_id": action_id, **request})
            return {"status": "shadow", "action_id": action_id,
                    "detail": "shadow mode: logged, nothing changed"}
        recent = self.store.count_auto_executed_since(now - 3_600_000)
        if recent >= self.x.max_auto_actions_per_hour:
            self.store.audit("rate_limited", {"recent": recent, **request})
            return {"status": "rate_limited",
                    "detail": f"{recent} automatic actions in the last hour; not acting"}
        return self._run(action_id, request, auto=True, now=now)

    def _run(self, action_id: str, request: dict, *, auto: bool, now: int) -> dict:
        action, args = request["action"], request["args"]
        try:
            detail, undo = self.actions.execute(action, args, action_id, self.store)
        except (Refused, Failed) as exc:
            kind = "refused" if isinstance(exc, Refused) else "failed"
            self.store.add_action({"id": action_id, "ts_ms": now, **request, "auto": auto,
                                   "status": "failed", "detail": str(exc)})
            self.store.audit(f"action_{kind}", {"action_id": action_id, "why": str(exc),
                                                **request})
            return {"status": kind, "action_id": action_id, "detail": str(exc)}
        self.store.add_action({"id": action_id, "ts_ms": now, **request, "auto": auto,
                               "status": "executed", "detail": detail, "undo": undo})
        self.store.audit("action_executed", {"action_id": action_id, "detail": detail,
                                             "auto": auto, **request})
        log.warning("executed %s (%s): %s", action, action_id, detail)
        return {"status": "executed", "action_id": action_id, "detail": detail}

    # ---- passkeys -----------------------------------------------------------------
    def _webauthn_ready(self) -> None:
        if not (self.x.rp_id and self.x.origin):
            raise Rejected("passkeys aren't configured (executor.rp_id / origin)")

    def new_enroll_code(self) -> str:
        """One-time code that authorizes registering a passkey. Root CLI only."""
        code = f"{secrets.randbelow(10**8):08d}"
        self.store.set_state("enroll", json.dumps({
            "hash": hashlib.sha256(code.encode()).hexdigest(),
            "expires_ms": _now() + ENROLL_TTL_MS, "tries": 0}))
        self.store.audit("enroll_code_created", {})
        return code

    def _check_enroll_code(self, code: str, consume: bool) -> None:
        raw = self.store.get_state("enroll")
        rec = json.loads(raw) if raw else None
        if not rec or rec["expires_ms"] <= _now() or rec["tries"] >= 5:
            raise Rejected("no valid enrollment code; run `sudo bastion passkey enroll`")
        good = hmac.compare_digest(rec["hash"],
                                   hashlib.sha256(str(code).encode()).hexdigest())
        if not good:
            rec["tries"] += 1
            self.store.set_state("enroll", json.dumps(rec))
            raise Rejected("wrong enrollment code")
        if consume:
            self.store.del_state("enroll")

    def register_options(self, code: str) -> dict:
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        self._webauthn_ready()
        self._check_enroll_code(code, consume=False)
        opts = generate_registration_options(
            rp_id=self.x.rp_id, rp_name="Bastion", user_name="bastion-owner",
            user_display_name="Bastion owner",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED))
        cid = uuid.uuid4().hex
        self.store.add_challenge(cid, "register", "passkey", opts.challenge,
                                 _now() + CHALLENGE_TTL_MS)
        return {"challenge_id": cid, "options": json.loads(options_to_json(opts))}

    def register_verify(self, code: str, challenge_id: str, credential: dict,
                        name: str = "") -> dict:
        from webauthn import verify_registration_response

        self._webauthn_ready()
        self._check_enroll_code(code, consume=False)
        now = _now()
        challenge = self.store.use_challenge(challenge_id, "register", "passkey", now)
        if challenge is None:
            raise Rejected("registration challenge expired; start again")
        try:
            v = verify_registration_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=self.x.rp_id, expected_origin=self.x.origin,
                require_user_verification=True)
        except Exception as exc:
            self.store.audit("passkey_register_failed", {"why": str(exc)[:200]})
            raise Rejected(f"passkey registration failed: {exc}") from exc
        self._check_enroll_code(code, consume=True)
        cred_id = _b64u(v.credential_id)
        self.store.add_passkey(cred_id, v.credential_public_key, v.sign_count,
                               (name or "passkey")[:60], now)
        self.store.audit("passkey_registered", {"credential_id": cred_id,
                                                "name": (name or "passkey")[:60]})
        return {"registered": True, "credential_id": cred_id}

    def _assertion_options(self, purpose: str, subject: str, binding: str) -> dict:
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers import base64url_to_bytes
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        self._webauthn_ready()
        keys = self.store.list_passkeys()
        if not keys:
            raise Rejected("no passkey is registered; run `sudo bastion passkey enroll`")
        # The challenge commits to what is being authorized, not just to randomness.
        challenge = hashlib.sha256(
            b"bastion-v1|" + secrets.token_bytes(32) + f"|{purpose}|{subject}|{binding}"
            .encode()).digest()
        opts = generate_authentication_options(
            rp_id=self.x.rp_id, challenge=challenge,
            allow_credentials=[PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(k["credential_id"])) for k in keys],
            user_verification=UserVerificationRequirement.REQUIRED)
        cid = uuid.uuid4().hex
        self.store.add_challenge(cid, purpose, subject, challenge, _now() + CHALLENGE_TTL_MS)
        return {"challenge_id": cid, "options": json.loads(options_to_json(opts))}

    def _verify_assertion(self, purpose: str, subject: str, challenge_id: str,
                          credential: dict) -> str:
        from webauthn import verify_authentication_response

        now = _now()
        challenge = self.store.use_challenge(challenge_id, purpose, subject, now)
        if challenge is None:
            raise Rejected("approval challenge expired or already used; try again")
        cred_id = str(credential.get("id", "")) if isinstance(credential, dict) else ""
        key = next((k for k in self.store.list_passkeys()
                    if k["credential_id"] == cred_id), None)
        if key is None:
            raise Rejected("unknown passkey")
        try:
            v = verify_authentication_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=self.x.rp_id, expected_origin=self.x.origin,
                credential_public_key=key["public_key"],
                credential_current_sign_count=key["sign_count"],
                require_user_verification=True)
        except Exception as exc:
            self.store.audit("passkey_assertion_failed", {"purpose": purpose,
                                                          "subject": subject,
                                                          "why": str(exc)[:200]})
            raise Rejected(f"passkey check failed: {exc}") from exc
        self.store.update_sign_count(cred_id, v.new_sign_count)
        return cred_id

    # ---- approvals ----------------------------------------------------------------
    def _pending(self, approval_id: str) -> dict:
        self.store.expire_approvals(_now())
        rec = self.store.get_approval(approval_id)
        if rec is None:
            raise Rejected("no such approval request")
        if rec["status"] != "pending":
            raise Rejected(f"this request is already {rec['status']}")
        return rec

    def approval_options(self, approval_id: str) -> dict:
        rec = self._pending(approval_id)
        return self._assertion_options("approve", approval_id, rec["action_hash"])

    def approve(self, approval_id: str, challenge_id: str, credential: dict) -> dict:
        self._pending(approval_id)
        cred = self._verify_assertion("approve", approval_id, challenge_id, credential)
        return self._execute_approved(approval_id, by=f"passkey:{cred[:12]}")

    def approve_local(self, approval_id: str) -> dict:
        """Approve from the root CLI on the Mac itself."""
        self._pending(approval_id)
        return self._execute_approved(approval_id, by="cli")

    def _execute_approved(self, approval_id: str, by: str) -> dict:
        now = _now()
        if not self.store.claim_approval(approval_id, now):
            raise Rejected("this request was already decided")
        rec = self.store.get_approval(approval_id)
        request = rec["command"]   # the stored request, never anything from the caller
        self.store.audit("approval_granted", {"approval_id": approval_id, "by": by,
                                              "action_hash": rec["action_hash"]})
        result = self._run(uuid.uuid4().hex[:16], request, auto=False, now=now)
        self.store.finish_approval(approval_id,
                                   "approved" if result["status"] == "executed" else "failed",
                                   result["detail"], now)
        return {**result, "approval_id": approval_id}

    def deny(self, approval_id: str, by: str = "console") -> dict:
        self._pending(approval_id)
        self.store.finish_approval(approval_id, "denied", f"denied via {by}", _now())
        self.store.audit("approval_denied", {"approval_id": approval_id, "by": by})
        return {"status": "denied", "approval_id": approval_id}

    # ---- undo ---------------------------------------------------------------------
    def _undoable(self, action_id: str) -> dict:
        rec = self.store.get_action(action_id)
        if rec is None:
            raise Rejected("no such action")
        if rec["tier"] != 1 or rec["status"] != "executed":
            raise Rejected(f"this action is {rec['status']} and can't be undone")
        return rec

    def undo_options(self, action_id: str) -> dict:
        rec = self._undoable(action_id)
        return self._assertion_options("undo", action_id,
                                       action_hash(rec["action"], rec["args"]))

    def undo(self, action_id: str, challenge_id: str, credential: dict) -> dict:
        self._undoable(action_id)
        cred = self._verify_assertion("undo", action_id, challenge_id, credential)
        return self._undo(action_id, by=f"passkey:{cred[:12]}")

    def undo_local(self, action_id: str) -> dict:
        self._undoable(action_id)
        return self._undo(action_id, by="cli")

    def _undo(self, action_id: str, by: str) -> dict:
        rec = self._undoable(action_id)
        try:
            detail = self.actions.undo(rec["action"], rec["undo"])
        except (Refused, Failed) as exc:
            self.store.audit("undo_failed", {"action_id": action_id, "why": str(exc),
                                             "by": by})
            return {"status": "failed", "action_id": action_id, "detail": str(exc)}
        self.store.set_action_status(action_id, "undone")
        self.store.audit("action_undone", {"action_id": action_id, "detail": detail,
                                           "by": by})
        return {"status": "undone", "action_id": action_id, "detail": detail}

    # ---- views (for the console) --------------------------------------------------
    def list_actions(self, limit: int = 50) -> list[dict]:
        keep = ("id", "ts_ms", "action", "args", "tier", "auto", "status", "incident_id",
                "agent", "reason", "detail")
        return [{k: a[k] for k in keep} for a in self.store.list_actions(limit)]

    def list_approvals(self, status: str | None = "pending") -> list[dict]:
        self.store.expire_approvals(_now())
        keep = ("id", "created_ms", "expires_ms", "command", "status", "decided_ms", "result")
        return [{k: a[k] for k in keep} for a in self.store.list_approvals(status)]
