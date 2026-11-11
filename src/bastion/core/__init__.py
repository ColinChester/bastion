"""Bastion core (Phase 2): the Warden orchestrator and its domain agents.

Runs in a container, separate from bastiond. It can reach the Mac only through
bastiond's read-only edge API, so nothing an agent does here can change the system.
"""
