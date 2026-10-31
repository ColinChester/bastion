"""Configuration loading.

The daemon reads a TOML file (default: /Library/Application Support/Bastion/config.toml).
Every key has a default, so a missing or partial file still yields a working config.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/Library/Application Support/Bastion/config.toml")
ENV_CONFIG = "BASTION_CONFIG"


@dataclass
class OsquerySource:
    enabled: bool = True
    results_log: str = "/var/log/osquery/osqueryd.results.log"


@dataclass
class SantaSource:
    enabled: bool = True
    log: str = "/var/db/santa/santa.log"


@dataclass
class UnifiedLogSource:
    enabled: bool = True
    # Combined with OR into one `log stream` process. Keep these narrow: `log stream`
    # costs CPU proportional to what the predicate lets through.
    predicates: list[str] = field(
        default_factory=lambda: [
            'process == "sudo"',
            'subsystem BEGINSWITH "com.objective-see"',
        ]
    )


@dataclass
class NotifyConfig:
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    # "daily": one summary push a day. "high_live": daily + live push for high severity.
    # "off": no pushes.
    mode: str = "daily"
    daily_summary_time: str = "08:30"


@dataclass
class BaselineConfig:
    learning_days: int = 14
    # Paths containing any of these markers count as "built locally" and never raise
    # first-seen binary findings. Case-insensitive substring match.
    dev_path_markers: list[str] = field(
        default_factory=lambda: [
            "/git/",
            "/target/debug/",
            "/target/release/",
            "/.build/",
            "/build/",
            "/node_modules/",
            "/DerivedData/",
            "/PycharmProjects/",
            "/eclipse-workspace/",
        ]
    )


@dataclass
class Config:
    data_dir: Path = Path("/Library/Application Support/Bastion")
    rules_dir: Path | None = None
    retention_days: int = 30
    osquery: OsquerySource = field(default_factory=OsquerySource)
    santa: SantaSource = field(default_factory=SantaSource)
    unified_log: UnifiedLogSource = field(default_factory=UnifiedLogSource)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    extra_redaction_patterns: list[str] = field(default_factory=list)
    detection_dedupe_seconds: int = 60

    @property
    def db_path(self) -> Path:
        return self.data_dir / "bastion.db"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def resolved_rules_dir(self) -> Path:
        if self.rules_dir:
            return self.rules_dir
        return bundled_rules_dir()


def bundled_rules_dir() -> Path:
    """Rules shipped with the package (wheel) or, in a source checkout, the repo's rules/."""
    pkg_rules = Path(__file__).parent / "_rules"
    if pkg_rules.is_dir():
        return pkg_rules
    return Path(__file__).resolve().parents[2] / "rules"


def _merge(dc, values: dict):
    for key, value in values.items():
        if not hasattr(dc, key):
            raise ValueError(f"unknown config key: {key}")
        current = getattr(dc, key)
        if hasattr(current, "__dataclass_fields__") and isinstance(value, dict):
            _merge(current, value)
        elif isinstance(current, Path) or key in {"rules_dir", "data_dir"}:
            setattr(dc, key, Path(value) if value else None)
        else:
            setattr(dc, key, value)


class ConfigPermissionError(PermissionError):
    """The config file exists but this user can't read it (it's root-only by design)."""


def load_config(path: Path | str | None = None) -> Config:
    """Load config from `path`, $BASTION_CONFIG, or the default location."""
    cfg = Config()
    candidate = Path(path) if path else Path(os.environ.get(ENV_CONFIG, DEFAULT_CONFIG_PATH))
    try:
        exists = candidate.is_file()
        if exists:
            with candidate.open("rb") as fh:
                raw = tomllib.load(fh)
    except PermissionError as exc:
        raise ConfigPermissionError(f"can't read {candidate} (root-only)") from exc
    if exists:
        sources = raw.pop("sources", {})
        for name in ("osquery", "santa", "unified_log"):
            if name in sources:
                _merge(getattr(cfg, name), sources[name])
        _merge(cfg, raw)
    if cfg.data_dir is None:
        cfg.data_dir = Config().data_dir
    return cfg
