"""False-positive review report for the shadow period.

The Phase 1 gate is "one week of events with a reviewed false-positive list". This
report groups every detection by rule, shows what triggered it (redacted), and gives
a checkbox per distinct subject so you can mark each one benign or real. Filters you
decide on go back into the rule files' `filter_*` selections.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime

from bastion import ocsf
from bastion.store import Store


def _subject_line(f: dict) -> str:
    proc = ocsf.get(f, "process.file.path") or ocsf.get(f, "actor.process.file.path") or ""
    target = ocsf.get(f, "file.path") or ""
    dst = ocsf.get(f, "dst_endpoint.ip")
    port = ocsf.get(f, "src_endpoint.port")
    label = ocsf.get(f, "unmapped.persistence.label")
    bits = [b for b in (proc, target and f"-> {target}", label and f"({label})",
                        dst and f"-> {dst}", port and f"listening :{port}") if b]
    return " ".join(bits) or "(no subject)"


def build_report(store: Store, days: int = 7, now_ms: int | None = None) -> str:
    now_ms = now_ms or int(time.time() * 1000)
    since = now_ms - days * 86_400_000
    dets = list(store.iter_detections(since))
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for d in dets:
        by_rule[(d["severity"], d["title"], d["rule_id"])].append(d)

    out = [
        f"# Bastion false-positive review ({days} days)",
        "",
        f"Generated {datetime.fromtimestamp(now_ms / 1000):%Y-%m-%d %H:%M}. "
        f"{sum(d['hits'] for d in dets)} hits, {len(dets)} distinct detections, "
        f"{len(by_rule)} rules.",
        "",
        "For each subject, tick **benign** or **real**. Benign subjects become `filter_*` "
        "entries in the rule (or baseline entries for first-seen findings).",
        "",
    ]
    events = store.count_events_by_source(since)
    out.append("Events stored by source: "
               + (", ".join(f"{k} {v:,}" for k, v in events.items()) or "none"))
    out.append("Baseline size: "
               + (", ".join(f"{k} {v:,}" for k, v in store.baseline_size().items()) or "empty"))
    out.append("")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for (sev, title, rule_id), items in sorted(by_rule.items(),
                                               key=lambda kv: (order.get(kv[0][0], 9),
                                                               -len(kv[1]))):
        hits = sum(i["hits"] for i in items)
        out += [f"## [{sev}] {title}", "", f"Rule `{rule_id}`: {hits} hits.", ""]
        subjects: Counter[str] = Counter()
        samples: dict[str, str] = {}
        for i in items:
            s = _subject_line(i["finding"]).replace("`", "'")
            subjects[s] += i["hits"]
            cmd = ocsf.get(i["finding"], "process.cmd_line") or ocsf.get(
                i["finding"], "actor.process.cmd_line")
            if cmd and s not in samples:
                samples[s] = cmd[:300].replace("`", "'")
        for s, n in subjects.most_common(25):
            out.append(f"- [ ] benign  [ ] real  — `{s}` ×{n}")
            if s in samples:
                out.append(f"  - sample: `{samples[s]}`")
        if len(subjects) > 25:
            out.append(f"- ...{len(subjects) - 25} more subjects")
        out.append("")
    if not dets:
        out.append("No detections in this window.")
    return "\n".join(out)
