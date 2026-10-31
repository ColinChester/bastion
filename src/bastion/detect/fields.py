"""Sigma logsource and field mapping onto Bastion's OCSF events.

Rules are written in standard Sigma syntax with Sigma-style field names (Image,
CommandLine, TargetFilename, ...). This module says which OCSF events a logsource
covers and where each field lives. A field name containing a dot is read as a raw
OCSF path, which is the escape hatch for anything not mapped here.

Custom macOS logsource categories (documented in docs/detections.md):
    persistence      launchd / login-item additions and removals (osquery differential)
    network_listen   a new listening socket (osquery differential)
    inventory        other osquery inventory changes (apps, system extensions, roots)
"""

from __future__ import annotations

from bastion import ocsf

# category -> predicate over an event
LOGSOURCE_FILTERS = {
    "process_creation": lambda e: e.get("class_uid") == 1007
    and e.get("activity_id") == ocsf.PROC_LAUNCH,
    "file_event": lambda e: e.get("class_uid") == 1001
    and "persistence" not in (e.get("unmapped") or {}),
    "persistence": lambda e: e.get("class_uid") == 1001
    and "persistence" in (e.get("unmapped") or {}),
    "network_connection": lambda e: e.get("class_uid") == 4001
    and e.get("activity_id") == ocsf.NET_OPEN,
    "network_listen": lambda e: e.get("class_uid") == 4001
    and e.get("activity_id") == ocsf.NET_LISTEN,
    "inventory": lambda e: e.get("class_uid") == 0
    and "inventory" in (e.get("unmapped") or {}),
    "unified_log": lambda e: e.get("class_uid") == 0
    and e.get("metadata", {}).get("log_name") == "unified_log",
}

_COMMON = {
    "Source": "metadata.log_name",
    "InitialSnapshot": "unmapped.initial_snapshot",
}

FIELD_MAP: dict[str, dict[str, str]] = {
    "process_creation": {
        "Image": "process.file.path",
        "CommandLine": "process.cmd_line",
        "ParentImage": "actor.process.file.path",
        "ParentCommandLine": "actor.process.cmd_line",
        "User": "process.user.name",
        "CurrentDirectory": "process.working_directory",
        "TeamId": "unmapped.team_id",
        "SigningId": "unmapped.signing_id",
        "PlatformBinary": "unmapped.platform_binary",
        "CodesigningFlags": "unmapped.codesigning_flags",
        "SantaDecision": "unmapped.santa.decision",
        "SantaReason": "unmapped.santa.reason",
    },
    "file_event": {
        "TargetFilename": "file.path",
        "SourceFilename": "file.unmapped_source_path",
        "Image": "actor.process.file.path",
        "CommandLine": "actor.process.cmd_line",
        "FileActivity": "activity_name",
        "ActivityId": "activity_id",
    },
    "persistence": {
        "TargetFilename": "file.path",
        "PersistenceType": "unmapped.persistence.type",
        "Label": "unmapped.persistence.label",
        "Program": "unmapped.persistence.program",
        "ActivityId": "activity_id",
    },
    "network_connection": {
        "Image": "process.file.path",
        "DestinationIp": "dst_endpoint.ip",
        "DestinationPort": "dst_endpoint.port",
        "DestinationHostname": "dst_endpoint.hostname",
    },
    "network_listen": {
        "Image": "process.file.path",
        "SourceIp": "src_endpoint.ip",
        "SourcePort": "src_endpoint.port",
    },
    "inventory": {
        "InventoryKind": "unmapped.inventory.kind",
        "Action": "unmapped.inventory.action",
        "CommonName": "unmapped.inventory.row.common_name",
        "Sha1": "unmapped.inventory.row.sha1",
        "Identifier": "unmapped.inventory.row.identifier",
        "TeamId": "unmapped.inventory.row.team",
    },
    "unified_log": {
        "Message": "message",
        "Image": "actor.process.file.path",
        "Subsystem": "unmapped.subsystem",
    },
}


def resolve_field(category: str, field: str) -> str:
    if "." in field:
        return field
    mapping = FIELD_MAP.get(category, {})
    if field in mapping:
        return mapping[field]
    if field in _COMMON:
        return _COMMON[field]
    raise KeyError(f"field {field!r} is not mapped for logsource category {category!r}")
