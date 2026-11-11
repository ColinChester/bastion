# Phase 2: orchestrator and agents

Phase 2 adds the part that thinks. Each detection from Phase 1 is investigated by a
domain agent, reviewed by the Warden orchestrator, and recorded as a structured incident
you can read on a page. It is still observe-only: agents can read telemetry and propose
actions, and nothing executes.

```
bastiond (root, on the Mac)                containers (OrbStack)
┌──────────────────────────────┐          ┌───────────────────────────────────────────┐
│ sensors → rules → detections │  edge    │ core: route → Sentry | Anchor | Tide      │
│ edge API  127.0.0.1:8765     │◀─────────│        → Warden review → incident         │
│  read-only, typed, token     │  HTTP    │ web:   incident page  127.0.0.1:8787      │
└──────────────────────────────┘          │ ntfy:  pushes         127.0.0.1:8090      │
                                          │ phoenix: traces       127.0.0.1:6006      │
                                          └───────────────────────────────────────────┘
        phone ── Tailscale Serve (tailnet only) ──▶ incident page, ntfy
```

## How one detection is handled

1. **Outbox.** The core polls bastiond's edge API for untriaged detections. Detections
   older than the core's first start are treated as history and skipped.
2. **Route** (code, no model). Persistence items and shell profiles go to **Anchor**,
   network findings to **Tide**, everything else to **Sentry**.
3. **Agent** (Claude Haiku 5.5). It may call its own read-only tools up to 6 times
   (process tree, binary history, file activity, related detections…), then must return an
   `AgentFinding`: verdict, confidence, summary, evidence and proposed actions.
4. **Warden review** (Claude Sonnet 5.5). Only when the finding isn't a confident benign.
   Warden checks the reasoning and returns the final `WardenDecision`.
5. **Guardrails in code.** Whatever the models said: malicious always notifies; a benign
   decision can't override an analyst's "malicious"; headlines with paths are replaced.
6. **Record and notify.** The incident is saved, the detection acknowledged, and a push
   sent if needed. Everything else waits for the 08:30 digest.

## Safety properties

- **Agents can't change anything.** The container reaches the Mac only through the edge
  API, which has fixed read-only queries and one write: "mark detection triaged".
- **Each agent sees only its own tools.** Proposed actions outside its domain are dropped.
- **Telemetry is untrusted input.** File names and command lines are wrapped as data, and
  prompts tell agents to treat instructions inside them as evidence of an attack. Because
  agents can only read, a successful injection could at worst mislabel one incident,
  which is why the guardrails in step 5 are in code.
- **Spend caps in code:** $0.15 per incident, $1.50 per day, $25 per month (change in
  `deploy/.env`). When a cap is hit, triage pauses and tells you once.
- **Secrets:** the API key and edge token live only in `deploy/.env` (mode 600, never
  committed). Telemetry was redacted before storage, so models never see raw secrets.
- **Pushes** still carry no paths or command lines. Traces stay in the local Phoenix.

## Setup (about 15 minutes)

You need: Phase 1 running, Tailscale on the Mac and phone, and an Anthropic API key from
<https://console.anthropic.com> (set a $25/month limit on its workspace).

```bash
cd ~/git/bastion && git pull
./scripts/setup-phase2.sh
```

The script installs OrbStack if needed, turns on the edge API, asks you to paste the API
key (hidden, stored only in `deploy/.env`), starts the containers, shares the incident
page and ntfy with your tailnet, and runs the checks. For phone access, MagicDNS and
HTTPS certificates must be on in the Tailscale admin console (DNS page).

Then on the iPhone, in the ntfy app, add a subscription with **Use another server** set
to the URL the script prints, and the new topic.

## Everyday commands

```bash
alias bc='docker compose -f ~/git/bastion/deploy/docker-compose.yml'
bc exec core bastion-core check --push    # edge API, model key, push, budget
bc logs -f core                            # watch triage happen
bc exec core bastion-core digest           # preview the daily digest
bc exec core bastion-core eval             # grade agents on the labeled set
bc up -d --build                           # after a git pull
./scripts/bootstrap.sh --update            # after a git pull that changes bastiond
```

Incident page: <http://localhost:8787>. Traces: <http://localhost:6006>.

## The Phase 2 gate

*Every rule hit produces a correct structured finding on the labeled set.*

The labeled set is `tests/labeled_events/phase1-labels.yml`: the 16 trigger-test
detections (expected: suspicious or malicious) and the false positives found in the
shadow weeks (expected: benign). To run it:

```bash
./scripts/test-triggers.sh        # fresh true positives (you'll get pushes for these)
bc exec core bastion-core eval
```

The report lists each case as PASS, MISS (threat called benign), FALSE ALARM or UNSURE.
Results are recorded in [phase2-eval.md](phase2-eval.md). The gate was met on Nov 11
(45 of 46 correct, no missed threats or false alarms).
