# Bastion

Bastion is an autonomous security agent system for a single Mac. When it's finished, an
orchestrator agent will triage what the sensors see, contain threats on its own, and ask
for approval on the phone before doing anything destructive.

**Where it is now:** Phases 0–1 (sensors and detections) are complete, and Phase 2
(the orchestrator and first three agents) is being built. Everything is observe-only: it
watches, investigates and reports, and blocks nothing.

- **Sensor layer** (`bastiond`, below): records what happens on the Mac and raises
  detections.
- **Agent layer** ([docs/phase2.md](docs/phase2.md)): a LangGraph orchestrator (Warden)
  routes each detection to a domain agent (Sentry for execution, Anchor for persistence,
  Tide for network). The agent investigates with read-only tools and returns a structured
  verdict, which you read on an incident page or get as a push.

```
osquery (Endpoint Security) ─┐
Santa (Monitor mode) ────────┼─▶ bastiond: normalize to OCSF ─▶ redact ─▶ SQLite ─▶ Sigma + first-seen ─▶ detections
unified log (sudo, LuLu…) ───┘                                                                         └─▶ daily push (ntfy)
LuLu · BlockBlock · KnockKnock: Objective-See tools, installed alongside
```

## What's here

- **bastiond**: a small Python daemon. It tails the osquery and Santa logs (checkpointed,
  rotation-safe) and the unified log. Every event is mapped to
  [OCSF](https://schema.ocsf.io) and has secrets redacted *before* it's stored.
- **Detections**:
  - 15 [Sigma](https://sigmahq.io) rules for macOS tradecraft (persistence, credential
    access, defense evasion, fake password prompts…), each with true-positive and
    benign-twin tests.
  - Stateful first-seen analytics (new binary, new egress, new listener) with a 14-day
    learning window.
  - A correlation for `curl | sh` typed into Terminal.
  - See [docs/detections.md](docs/detections.md).
- **Posture audit** (`bastion posture`):
  - System: FileVault, SIP, Gatekeeper, firewall, updates, sharing services, listeners,
    background items and TCC grants.
  - Developer exposure: plaintext secrets in dotfiles, unencrypted SSH keys, browser
    extensions, npm install scripts.
  - AI coding-agent settings (Claude Code, Codex, MCP servers).
- **Triage helper** (`bastion whoowns PATH`): answers "what created this folder?" using
  launchd, receipts, open handles and code signatures.
- **Setup**: one script installs and configures osquery, Santa, the Objective-See tools and
  bastiond as LaunchDaemons. Package signatures are verified before install.

## Quick start (macOS 15+, Apple silicon, Homebrew)

```bash
git clone https://github.com/ColinChester/bastion.git ~/git/bastion
cd ~/git/bastion
./scripts/bootstrap.sh            # add --dry-run to print every command first
```

The script stops for the approvals only you can give (Santa profile, system extensions,
Full Disk Access). [docs/setup-checklist.md](docs/setup-checklist.md) walks through them.

## Commands

Commands that read Bastion's data or config need `sudo`, because that folder is root-only.

| Command | What it does |
| --- | --- |
| `sudo bastion status` | heartbeat, sensor freshness, 24 h event and detection counts |
| `sudo bastion doctor` | sensor health, with the exact fix for anything wrong |
| `sudo bastion posture [--quick] [--out DIR]` | posture audit to Markdown and JSON |
| `sudo bastion whoowns PATH` | ownership triage for a file or folder |
| `sudo bastion report [--days 7] [--out FILE]` | false-positive review sheet, grouped by rule |
| `sudo bastion test-push` | send a test notification |
| `sudo bastion detections [--since EPOCH]` | detections since a time (`--json` for scripts) |
| `./scripts/test-triggers.sh` | fire every detection once with harmless decoys and check it was recorded |
| `./scripts/bootstrap.sh --update` | reinstall and restart Bastion after a `git pull` |
| `./scripts/setup-phase2.sh` | set up the agent layer (containers, edge API, pushes) |
| `bastion rules [--dir rules]` | load and validate the Sigma rules |
| `bastion replay {osquery,santa,unified_log} FILE` | run recorded logs through the pipeline into a scratch DB |

## Privacy

- Secrets are redacted before anything is written to disk.
- Process environment variables aren't collected.
- Push notifications contain rule titles and counts only, never paths or command lines.
- All data stays in `/Library/Application Support/Bastion` (root-only, 30-day retention).

## Development

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest -q && .venv/bin/ruff check .
```

Tests run anywhere, with no macOS needed: sensors are replaced by recorded log lines, and
system commands by a fake runner.

## Roadmap

| Phase | Scope |
| --- | --- |
| 0–1 ✅ | Sensors, OCSF pipeline, redaction, Sigma rules, posture audit, shadow week ([review](docs/phase1-review.md)) |
| 2 🚧 | LangGraph orchestrator and three core agents, self-hosted ntfy, daily digest, tracing, read-only incident page |
| 3 | Per-domain gateways with Cedar policies, passkey-signed approvals, undo log, first autonomous containment (after 14 days in shadow) |
| 4 | Move to an Oracle Cloud VM over Tailscale, NATS JetStream, dead-man's switch, remaining agents |
| 5 | Validation with Atomic Red Team and prompt-injection tests, metrics, demo |

Design choices so far are recorded in [docs/decisions.md](docs/decisions.md), the Phase 1 shadow-week review in
[docs/phase1-review.md](docs/phase1-review.md), and every
problem hit so far, with its cause and fix, in [docs/issues-log.md](docs/issues-log.md).
