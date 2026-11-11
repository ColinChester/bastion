"""Evaluation against the labeled set (the Phase 2 gate).

The labeled set is the Phase 1 review: every detection subject from the shadow weeks,
classified as a true positive (trigger test) or a false positive (benign). Labels match
detections by rule title plus text that must appear in the detection. The detections
themselves stay in bastiond's database on the Mac; only the labels live in the repo.

Scoring, from worst to mildest failure:
- MISS:        a labeled threat was called benign
- FALSE ALARM: labeled benign was called suspicious or malicious
- UNSURE:      inconclusive, either way
A case passes when a threat is called suspicious or malicious, or benign is called benign.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from bastion.core.corestore import CoreStore
from bastion.core.edge import Edge
from bastion.core.graph import triage
from bastion.core.models import ModelClient
from bastion.core.schemas import Incident, Verdict
from bastion.core.settings import Settings

DEFAULT_LABELS = Path("tests/labeled_events/phase1-labels.yml")


@dataclass
class Label:
    name: str
    expect: str            # "threat" or "benign"
    rule: str
    contains: list[str]

    def matches(self, detection: dict) -> bool:
        if detection.get("title") != self.rule:
            return False
        text = json.dumps(detection.get("subject", {}))
        return all(c in text for c in self.contains)


def load_labels(path: Path) -> list[Label]:
    labels = []
    for raw in yaml.safe_load(path.read_text()):
        if raw["expect"] not in ("threat", "benign"):
            raise ValueError(f"label {raw['name']}: expect must be threat or benign")
        labels.append(Label(raw["name"], raw["expect"], raw["rule"],
                            list(raw.get("contains", []))))
    return labels


def grade(expect: str, verdict: Verdict) -> str:
    if verdict == Verdict.INCONCLUSIVE:
        return "UNSURE"
    flagged = verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    if expect == "threat":
        return "PASS" if flagged else "MISS"
    return "FALSE ALARM" if flagged else "PASS"


@dataclass
class Case:
    label: Label
    detection: dict
    incident: Incident | None = None
    grade: str = ""


def select_cases(labels: list[Label], detections: list[dict], per_label: int) -> list[Case]:
    """Newest `per_label` detections for each label. First matching label wins."""
    cases: list[Case] = []
    taken: dict[str, int] = {}
    for det in sorted(detections, key=lambda d: d["time_ms"], reverse=True):
        label = next((lb for lb in labels if lb.matches(det)), None)
        if label and taken.get(label.name, 0) < per_label:
            taken[label.name] = taken.get(label.name, 0) + 1
            cases.append(Case(label, det))
    return cases


def run_eval(*, settings: Settings, model: ModelClient, edge: Edge, labels: list[Label],
             days: int = 21, per_label: int = 2) -> tuple[list[Case], list[str]]:
    """Triage labeled detections without acknowledging, saving or notifying."""
    now = int(time.time() * 1000)
    detections: list[dict] = []
    for d in range(days):  # day-sized windows keep each reply small
        start = now - (d + 1) * 86_400_000
        detections += edge.query("detections-window", start_ms=start,
                                 end_ms=start + 86_400_000, limit=500) or []
    unique = {d["detection_id"]: d for d in detections}
    cases = select_cases(labels, list(unique.values()), per_label)
    scratch = CoreStore(":memory:", settings.timezone)  # eval spend stays out of the ledger
    for case in cases:
        case.incident = triage(case.detection, settings=settings, model=model, edge=edge,
                               store=scratch)
        case.grade = grade(case.label.expect, case.incident.decision.verdict)
    covered = {c.label.name for c in cases}
    return cases, [lb.name for lb in labels if lb.name not in covered]


def report(cases: list[Case], uncovered: list[str], settings: Settings) -> str:
    n = len(cases)
    passed = sum(c.grade == "PASS" for c in cases)
    cost = sum(c.incident.cost_usd for c in cases if c.incident)
    lines = [
        f"# Bastion evaluation ({time.strftime('%Y-%m-%d %H:%M')})", "",
        f"Models: agents `{settings.agent_model}`, Warden `{settings.warden_model}`.", "",
        f"**{passed} of {n} correct** · "
        f"{sum(c.grade == 'MISS' for c in cases)} missed threats · "
        f"{sum(c.grade == 'FALSE ALARM' for c in cases)} false alarms · "
        f"{sum(c.grade == 'UNSURE' for c in cases)} inconclusive · ${cost:.3f} spent", "",
        "| Result | Label | Expected | Verdict | Conf. | Agent | Tools | Summary |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in sorted(cases, key=lambda c: (c.grade == "PASS", c.label.name)):
        i = c.incident
        summary = i.decision.summary.replace("|", "/").replace("\n", " ")[:160]
        lines.append(f"| {c.grade} | {c.label.name} | {c.label.expect} | "
                     f"{i.decision.verdict.value} | {i.decision.confidence:.0%} | {i.domain} "
                     f"| {len(i.tool_calls)} | {summary} |")
    if uncovered:
        lines += ["", "No matching detection in the window for: " + ", ".join(uncovered)
                  + ". Run `./scripts/test-triggers.sh` to produce the trigger cases."]
    return "\n".join(lines) + "\n"
