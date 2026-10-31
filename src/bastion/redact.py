"""Secret redaction.

Command lines, environment variables, URLs and log messages routinely contain tokens.
Every string in an event passes through `redact_event` before it is stored or sent
anywhere, so secrets never reach the local database, the orchestrator or a model.

Patterns are deliberately specific (known token formats plus key=value pairs whose key
names a secret) to keep false redactions low. Add your own with
`extra_redaction_patterns` in config.toml.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

MASK = "[REDACTED]"

# (name, pattern). Whole match is replaced unless the pattern has a group named "secret",
# in which case only that group is replaced (keeps "password=" visible, hides the value).
_BUILTIN: list[tuple[str, str]] = [
    ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("openai_key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("bearer", r"(?i)\b(?:bearer|token)\s+(?P<secret>[A-Za-z0-9._~+/\-]{16,}=*)"),
    ("url_credentials", r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:(?P<secret>[^@\s/]+)@"),
    (
        "secret_assignment",
        # KEY=value, --key value, --key=value, "key": "value" where the key names a secret.
        r"(?i)(?:[A-Za-z0-9_\-]*(?:passw(?:or)?d|passwd|secret|token|api[_\-]?key|apikey"
        r"|access[_\-]?key|private[_\-]?key|auth|credential|session[_\-]?id)[A-Za-z0-9_\-]*)"
        r"[\"']?\s*(?:=|:|\s)\s*[\"']?(?P<secret>[^\s\"'&,;]{6,})",
    ),
    (
        "url_query_secret",
        r"(?i)[?&](?:access_token|token|key|api_key|apikey|sig|signature|secret|password|code)"
        r"=(?P<secret>[^&\s#]{6,})",
    ),
]

# Keys whose values are never useful to detection and often hold secrets.
_DROP_KEYS = {"env"}


class Redactor:
    def __init__(self, extra_patterns: Iterable[str] = ()):
        self._patterns = [(name, re.compile(p)) for name, p in _BUILTIN]
        for i, p in enumerate(extra_patterns):
            self._patterns.append((f"custom_{i}", re.compile(p)))

    def redact(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        for _, pattern in self._patterns:
            if "secret" in pattern.groupindex:
                text = pattern.sub(_mask_group, text)
            else:
                text = pattern.sub(MASK, text)
        return text

    def redact_event(self, obj):
        """Return a copy of `obj` with every string redacted and secret-bearing keys masked."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in _DROP_KEYS and isinstance(v, str) and v:
                    out[k] = MASK
                else:
                    out[k] = self.redact_event(v)
            return out
        if isinstance(obj, list):
            return [self.redact_event(v) for v in obj]
        if isinstance(obj, str):
            return self.redact(obj)
        return obj


def _mask_group(match: re.Match) -> str:
    start, end = match.span("secret")
    s0 = match.start()
    whole = match.group(0)
    return whole[: start - s0] + MASK + whole[end - s0 :]
