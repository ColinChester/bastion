"""Bastion: autonomous multi-agent endpoint security for macOS.

This package currently implements Phases 0 and 1 of the plan: the edge daemon
(`bastiond`) that collects telemetry, normalizes it to OCSF, redacts secrets,
stores it locally and runs Sigma detections in shadow mode, plus the Phase 0
tooling (posture checks, triage, push test, false-positive report).
"""

__version__ = "0.1.0"
