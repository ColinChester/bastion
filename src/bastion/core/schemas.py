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


# The fixed action vocabulary per domain (from the plan's agent roster). In Phase 2 these
# are recorded as proposals only: nothing executes until Phase 3's gateways exist.
ACTIONS: dict[str, tuple[str, ...]] = {
    "sentry": ("kill_process", "suspend_process", "quarantine_file", "santa_block_rule"),
    "anchor": ("disable_launch_item", "remove_login_item", "delete_plist"),
    "tide": ("block_destination", "cut_network"),
}
ALL_ACTIONS = tuple(a for acts in ACTIONS.values() for a in acts)


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


class ToolCallRecord(BaseModel):
    agent: str
    tool: str
    arguments: dict
    ok: bool
    result_chars: int = 0
    error: str | None = None


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
