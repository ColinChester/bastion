"""A small Sigma evaluator for Bastion's OCSF events.

Rules are standard Sigma YAML (validated with pySigma in the test suite). This module
evaluates the subset Bastion uses, directly in Python, so bastiond has no SIEM backend:

* selections: a map (fields ANDed) or a list of maps (ORed)
* values: a scalar or a list (ORed; `|all` makes it AND); `null` means missing or empty
* modifiers: contains, startswith, endswith, re, all, cased, exists
* plain strings match case-insensitively, with Sigma wildcards `*` and `?`
* conditions: and / or / not, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`

Anything outside the subset (keyword lists, aggregations, timeframes) makes the rule
fail to load with a clear error instead of silently mismatching.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bastion import ocsf
from bastion.detect.fields import LOGSOURCE_FILTERS, resolve_field

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased", "exists"}
SERVICE_CATEGORIES = {"unifiedlog": "unified_log", "osquery": "inventory"}


class SigmaError(ValueError):
    pass


Matcher = Callable[[dict], bool]


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    tags: list[str]
    category: str
    description: str
    path: Path | None
    matcher: Matcher = field(repr=False)
    falsepositives: list[str] = field(default_factory=list)

    def matches(self, event: dict) -> bool:
        return LOGSOURCE_FILTERS[self.category](event) and self.matcher(event)


# ---- value matching -----------------------------------------------------------------
def _as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _value_matcher(path: str, modifiers: list[str], expected: Any) -> Callable[[dict], bool]:
    cased = "cased" in modifiers
    mods = [m for m in modifiers if m not in ("all", "cased")]
    if "exists" in mods:
        want = bool(expected)
        return lambda e: (ocsf.get(e, path) not in (None, "")) == want

    if expected is None or expected == "":
        return lambda e: ocsf.get(e, path) in (None, "")

    if "re" in mods:
        rx = re.compile(str(expected))
        return lambda e: (v := ocsf.get(e, path)) is not None and bool(rx.search(_as_text(v)))

    exp = _as_text(expected)
    if not cased:
        exp = exp.lower()

    def norm(v):
        s = _as_text(v)
        return s if cased else s.lower()

    if "contains" in mods:
        return lambda e: (v := ocsf.get(e, path)) is not None and exp in norm(v)
    if "startswith" in mods:
        return lambda e: (v := ocsf.get(e, path)) is not None and norm(v).startswith(exp)
    if "endswith" in mods:
        return lambda e: (v := ocsf.get(e, path)) is not None and norm(v).endswith(exp)
    if any(ch in exp for ch in "*?"):
        rx = re.compile(fnmatch.translate(exp), 0 if cased else re.IGNORECASE)
        return lambda e: (v := ocsf.get(e, path)) is not None and bool(rx.match(_as_text(v)))
    return lambda e: (v := ocsf.get(e, path)) is not None and norm(v) == exp


def _field_matcher(category: str, key: str, value: Any) -> Matcher:
    name, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaError(f"unsupported modifier(s) {sorted(unknown)} on {key!r}")
    path = resolve_field(category, name)
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"empty value list for {key!r}")
    matchers = [_value_matcher(path, modifiers, v) for v in values]
    if "all" in modifiers:
        return lambda e: all(m(e) for m in matchers)
    return lambda e: any(m(e) for m in matchers)


def _selection_matcher(category: str, name: str, body: Any) -> Matcher:
    if isinstance(body, dict):
        parts = [_field_matcher(category, k, v) for k, v in body.items()]
        return lambda e: all(p(e) for p in parts)
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        alts = [_selection_matcher(category, name, x) for x in body]
        return lambda e: any(a(e) for a in alts)
    raise SigmaError(f"selection {name!r}: keyword lists are not supported; use field maps")


# ---- condition parsing --------------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+)\s*")


def _tokenize(cond: str) -> list[str]:
    pos, out = 0, []
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _CondParser:
    def __init__(self, tokens: list[str], selections: dict[str, Matcher]):
        self.t = tokens
        self.i = 0
        self.sel = selections

    def parse(self) -> Matcher:
        m = self._or()
        if self.i != len(self.t):
            raise SigmaError(f"unexpected token {self.t[self.i]!r} in condition")
        return m

    def _peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def _take(self):
        tok = self._peek()
        self.i += 1
        return tok

    def _or(self) -> Matcher:
        left = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def _and(self) -> Matcher:
        left = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def _not(self) -> Matcher:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self) -> Matcher:
        tok = self._take()
        if tok is None:
            raise SigmaError("condition ended unexpectedly")
        if tok == "(":
            m = self._or()
            if self._take() != ")":
                raise SigmaError("missing ')' in condition")
            return m
        if tok in ("1 of", "all of"):
            target = self._take()
            if target is None:
                raise SigmaError(f"'{tok}' needs a target")
            names = (list(self.sel) if target == "them"
                     else [n for n in self.sel if fnmatch.fnmatchcase(n, target)])
            if not names:
                raise SigmaError(f"'{tok} {target}' matches no selection")
            ms = [self.sel[n] for n in names]
            if tok == "1 of":
                return lambda e: any(m(e) for m in ms)
            return lambda e: all(m(e) for m in ms)
        if tok in self.sel:
            return self.sel[tok]
        raise SigmaError(f"condition references unknown selection {tok!r}")


# ---- loading ------------------------------------------------------------------------
def compile_rule(doc: dict, path: Path | None = None) -> SigmaRule:
    for key in ("title", "id", "logsource", "detection", "level"):
        if key not in doc:
            raise SigmaError(f"missing required key {key!r}")
    ls = doc["logsource"]
    category = ls.get("category") or SERVICE_CATEGORIES.get(ls.get("service", ""))
    if category not in LOGSOURCE_FILTERS:
        raise SigmaError(f"unsupported logsource {ls!r}")
    det = dict(doc["detection"])
    condition = det.pop("condition", None)
    if "timeframe" in det:
        raise SigmaError("timeframe/aggregation rules are not supported")
    if not isinstance(condition, str):
        raise SigmaError("condition must be a single string")
    selections = {name: _selection_matcher(category, name, body) for name, body in det.items()}
    matcher = _CondParser(_tokenize(condition), selections).parse()
    return SigmaRule(
        id=str(doc["id"]),
        title=doc["title"],
        level=doc["level"],
        tags=list(doc.get("tags", [])),
        category=category,
        description=doc.get("description", ""),
        path=path,
        matcher=matcher,
        falsepositives=list(doc.get("falsepositives", [])),
    )


def load_rules(rules_dir: Path) -> tuple[list[SigmaRule], list[str]]:
    """Load every *.yml under rules_dir. Returns (rules, errors)."""
    rules, errors = [], []
    for p in sorted(Path(rules_dir).rglob("*.yml")):
        try:
            for doc in yaml.safe_load_all(p.read_text()):
                if doc:
                    rules.append(compile_rule(doc, p))
        except (SigmaError, KeyError, yaml.YAMLError) as exc:
            errors.append(f"{p.name}: {exc}")
    return rules, errors
