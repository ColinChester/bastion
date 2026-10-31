"""Telemetry collectors.

Each collector yields raw records as `RawRecord(source, payload)` onto a shared queue.
Normalization to OCSF happens downstream in `bastion.normalize`.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class RawRecord:
    source: str  # "osquery" | "santa" | "unified_log"
    payload: Any
