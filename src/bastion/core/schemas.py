"""Structured outputs. Agents return these, never free text (validated with Pydantic)."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Verdict(StrEnum):
    BENIGN = "benign"              # expected activity; no action needed
    SUSPICIOUS = "suspicious"      # could be an attack; worth a human look
    MALICIOUS = "malicious"        # strong evidence of an attack
    INCONCLUSIVE = "inconclusive"  # not enough evidence, or the agent failed


# The fixed containment vocabulary per domain. An agent only names an action; the target
# comes from the detection (core/playbook.py), the gateway's Cedar policy decides whether
# it may run, and the executor on the Mac re-checks the target.
ACTIONS: dict[str, tuple[str, ...]] = {
    "sentry": ("suspend_process", "quarantine_file"),
    "anchor": ("disable_launch_item",),
    "tide": (),   # network blocking arrives with a later phase
}
ALL_ACTIONS = tuple(a for acts in ACTIONS.values() for a in acts)


# Why something is benign. Only the first three explain behavior by WHAT the software is;
# the rest describe who started it or what it is called, which an attacker can arrange
# (a pasted "fix" command runs from the user's own terminal, and a payload can be named
# "test"). A benign verdict resting on any other basis is turned into "suspicious" in code.
BenignBasis = Literal[
    "os_component",            # part of macOS, Apple platform binary doing its normal job
    "signed_vendor_software",  # a known vendor's signed app/updater doing its documented job
    "developer_toolchain",     # the user's compilers, package managers, CLIs doing their job
    "user_initiated",          # the user ran it themselves (not sufficient on its own)
    "security_test",           # looks like a test or simulation (not sufficient)
    "other",
]
TRUSTED_BENIGN_BASES = frozenset({"os_component", "signed_vendor_software",
                                  "developer_toolchain"})

_BASIS_HELP = ("Required when verdict is benign: what makes it legitimate. os_component, "
               "signed_vendor_software or developer_toolchain describe what the software IS. "
               "user_initiated and security_test do not make a technique safe: commands "
               "pasted by the user and payloads named 'test' are how real attacks look.")


class ProposedAction(BaseModel):
    action: str = Field(description="One of the actions available to this agent.")
    target: str = Field(max_length=400, description="What it applies to (pid, path, label…).")
    reason: str = Field(max_length=300)


class AgentFinding(BaseModel):
    """A domain agent's conclusion about one detection."""

    verdict: Verdict
    confidence: float = Field(ge=0, le=1, description="0 to 1. Be honest; 0.5 means unsure.")
    summary: str = Field(max_length=500, description="Two or three plain sentences: what "
                         "happened and why you reached this verdict.")
    reasoning: str = Field(max_length=2000, description="The evidence chain, citing what "
                           "each tool result showed.")
    evidence_event_ids: list[int] = Field(default_factory=list, max_length=20)
    attack_techniques: list[str] = Field(default_factory=list, max_length=8,
                                         description="MITRE ATT&CK IDs, e.g. T1553.001.")
    proposed_actions: list[ProposedAction] = Field(default_factory=list, max_length=4)
    benign_basis: BenignBasis | None = Field(default=None, description=_BASIS_HELP)

    @field_validator("attack_techniques")
    @classmethod
    def _technique_ids(cls, v: list[str]) -> list[str]:
        return [t.upper() for t in v if t.upper().startswith("T") and len(t) <= 12]


Severity = Literal["info", "low", "medium", "high", "critical"]


class WardenDecision(BaseModel):
    """The orchestrator's final call on an incident."""

    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    headline: str = Field(max_length=90, description="Short title for a phone notification. "
                          "No file paths, command lines or usernames.")
    summary: str = Field(max_length=600, description="What happened and what the user "
                         "should do, in plain language.")
    notify: bool = Field(description="True if the user should be told now rather than in "
                         "the daily digest.")
    agrees_with_agent: bool = True
    benign_basis: BenignBasis | None = Field(default=None, description=_BASIS_HELP)


class ToolCallRecord(BaseModel):
    agent: str
    tool: str
    arguments: dict
    ok: bool
    result_chars: int = 0
    error: str | None = None


class ActionResponse(BaseModel):
    """What happened to one proposed action after the gateway and executor saw it."""

    action: str
    status: str          # executed | shadow | pending_approval | denied | refused | ...
    detail: str = ""
    policy: str = ""     # auto | approval | deny
    policy_ids: list[str] = Field(default_factory=list)
    action_id: str | None = None
    approval_id: str | None = None
    follow_up_approval_id: str | None = None


class Incident(BaseModel):
    id: str
    detection_id: int
    created_ms: int
    rule_id: str
    title: str
    rule_severity: str
    domain: str
    detection: dict
    finding: AgentFinding
    decision: WardenDecision
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    cost_usd: float = 0.0
    models: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    responses: list[ActionResponse] = Field(default_factory=list)
