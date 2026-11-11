"""Core settings, read from environment variables (set in deploy/.env)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# USD per million tokens: (input, output, cache read, cache write). Checked against
# Anthropic's pricing page on 2026-11-11; update here if prices change.
DEFAULT_PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10, 2.50),
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
}
# Haiku 5.5 costs 5x for prompts over 100K tokens.
LONG_PROMPT_TOKENS = 100_000
LONG_PROMPT_MULTIPLIER = {"claude-haiku-5-5": 5.0}


def _f(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def _i(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass
class Settings:
    edge_url: str = "http://host.docker.internal:8765"
    edge_token: str = ""
    data_dir: Path = Path("/data")
    # Models (plan option B). Triage agents use the small model; Warden the larger one.
    agent_model: str = "claude-haiku-5-5"
    warden_model: str = "claude-sonnet-5-5"
    # Limits, enforced in code (not in prompts).
    max_tool_rounds: int = 6
    incident_cap_usd: float = 0.15
    daily_cap_usd: float = 1.50
    monthly_cap_usd: float = 25.0
    poll_seconds: int = 15
    backlog_hours: int = 0          # on first start, also triage detections this old
    # Notifications (self-hosted ntfy).
    ntfy_url: str = ""
    ntfy_topic: str = ""
    digest_time: str = "08:30"
    timezone: str = "America/New_York"
    console_url: str = ""           # link added to pushes, e.g. the tailnet URL of the page
    # Phase 3: where proposed actions go. Empty = observe only (nothing is proposed).
    gateway_url: str = ""
    gateway_token: str = ""
    prices: dict[str, tuple[float, float, float, float]] = field(
        default_factory=lambda: dict(DEFAULT_PRICES))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "core.db"

    @classmethod
    def from_env(cls) -> Settings:
        e = os.environ.get
        return cls(
            edge_url=e("BASTION_EDGE_URL", cls.edge_url).rstrip("/"),
            edge_token=e("BASTION_EDGE_TOKEN", ""),
            data_dir=Path(e("BASTION_DATA_DIR", "/data")),
            agent_model=e("BASTION_AGENT_MODEL", cls.agent_model),
            warden_model=e("BASTION_WARDEN_MODEL", cls.warden_model),
            max_tool_rounds=_i("BASTION_MAX_TOOL_ROUNDS", cls.max_tool_rounds),
            incident_cap_usd=_f("BASTION_INCIDENT_CAP_USD", cls.incident_cap_usd),
            daily_cap_usd=_f("BASTION_DAILY_CAP_USD", cls.daily_cap_usd),
            monthly_cap_usd=_f("BASTION_MONTHLY_CAP_USD", cls.monthly_cap_usd),
            poll_seconds=_i("BASTION_POLL_SECONDS", cls.poll_seconds),
            backlog_hours=_i("BASTION_BACKLOG_HOURS", cls.backlog_hours),
            ntfy_url=e("BASTION_NTFY_URL", "").rstrip("/"),
            ntfy_topic=e("BASTION_NTFY_TOPIC", ""),
            digest_time=e("BASTION_DIGEST_TIME", cls.digest_time),
            timezone=e("TZ", cls.timezone),
            console_url=e("BASTION_CONSOLE_URL", "").rstrip("/"),
            gateway_url=e("BASTION_GATEWAY_URL", "").rstrip("/"),
            gateway_token=e("BASTION_GATEWAY_TOKEN", ""),
        )
