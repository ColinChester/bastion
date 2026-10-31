# Detections

Bastion's detections are standard [Sigma](https://sigmahq.io) rules in `rules/`, evaluated
by bastiond's built-in engine (`src/bastion/detect/sigma.py`) against OCSF events. CI
also validates every rule with pySigma, and each rule has a true-positive and
benign-twin test in `tests/test_rules.py`.

## The 15 rules

| Level | Rule | ATT&CK |
| --- | --- | --- |
| high | Unsigned or ad-hoc signed binary run from a download folder | T1204.002 |
| high | Download piped into a shell | T1059.004, T1105 |
| high | AppleScript dialog asking for a password | T1056.002, T1059.002 |
| high | Keychain secrets read with the security CLI | T1555.001 |
| high | Gatekeeper disabled with spctl | T1553.001 |
| high | Attempt to stop or unload a security tool | T1562.001 |
| high | Local account created or added to the admin group | T1136.001, T1078.003 |
| high | Privacy (TCC) database tampering | T1548.006 |
| high | Credential store opened by an unexpected process | T1552.001, T1552.004, T1539 |
| medium | Execution from a temporary or shared folder | T1204.002 |
| medium | Binary executed from a hidden folder in the home directory | T1564.001 |
| medium | Quarantine attribute removed from a file | T1553.001 |
| medium | LaunchAgent or LaunchDaemon property list written | T1543.001, T1543.004 |
| medium | Shell startup file modified | T1546.004 |
| medium | New LaunchAgent, LaunchDaemon or login item | T1543.001, T1547.015 |

Plus stateful analytics in `detect/engine.py`, for things a single event can't show:

- **First-seen**: a non-Apple binary runs for the first time (low), a binary makes its first
  outbound connection (medium), a binary listens on a new port (medium). They only record
  during the 14-day learning window, then start alerting. Binaries under "built locally"
  paths (`baseline.dev_path_markers`) never trigger them.
- **Download piped into a shell (interactive)** (high): `curl URL | sh` typed into Terminal
  runs curl and sh as two sibling processes, and neither command line contains the pipe,
  so the Sigma rule can't see it. This fires when curl or wget and a shell or interpreter
  that reads stdin (no script argument, or `-s`) are started by the same parent within
  3 seconds.

## Logsources

| Sigma logsource | Bastion events | Fields |
| --- | --- | --- |
| `category: process_creation` | OCSF Process Activity (osquery `es_process_events`, Santa) | Image, CommandLine, ParentImage, ParentCommandLine, User, CurrentDirectory, TeamId, SigningId, PlatformBinary, CodesigningFlags, SantaDecision, SantaReason |
| `category: file_event` | OCSF File System Activity (`es_process_file_events`, FSEvents) | TargetFilename, SourceFilename, Image, CommandLine, FileActivity, ActivityId (1 create, 2 open/read, 3 update, 4 delete, 5 rename) |
| `category: persistence` *(custom)* | launchd / login-item changes from osquery | TargetFilename, PersistenceType, Label, Program, ActivityId |
| `category: network_connection` | outbound sockets | Image, DestinationIp, DestinationPort |
| `category: network_listen` *(custom)* | new listeners | Image, SourceIp, SourcePort |
| `category: inventory` *(custom)* | apps, system extensions, trusted roots | InventoryKind, Action, CommonName, Sha1, Identifier, TeamId |
| `service: unifiedlog` | `log stream` entries | Message, Image, Subsystem |

Any field containing a dot is read as a raw OCSF path (e.g. `process.file.path`).

Supported Sigma subset: field maps and lists of maps; value lists; modifiers `contains`,
`startswith`, `endswith`, `re`, `all`, `cased`, `exists`; `null` (missing or empty);
conditions with `and`/`or`/`not`/parentheses/`1 of`/`all of`. Keyword lists, aggregations
and timeframes are rejected at load time instead of silently not matching.

osquery's first differential result for each inventory query lists everything that
already exists. Bastion marks those events `initial_snapshot` and never alerts on them, so
installing Bastion doesn't produce "new LaunchAgent" alerts for every existing one.

## Tuning

Expected on install day: *Attempt to stop or unload a security tool* fires when
`bootstrap.sh` restarts osquery and bastiond with `launchctl bootout`. Mark those benign;
they're the script, not an attacker.

After the shadow week, `sudo bastion report` lists every subject per rule. For each
benign one, add it to that rule's `filter_*` selection. For example, if Parallels'
updater writes a LaunchAgent:

```yaml
  filter_known:
    TargetFilename|contains:
      - '/com.apple.'
      - '/com.parallels.'   # added after shadow week review
```

Then check and redeploy:

```bash
bastion rules --dir rules          # must say "0 errors"
.venv/bin/pytest tests/test_rules.py
./scripts/bootstrap.sh --skip-tools --no-checks   # reinstalls the package with new rules
```

Test any rule against recorded data without touching the live database:

```bash
bastion replay osquery /var/log/osquery/osqueryd.results.log --learned
```
