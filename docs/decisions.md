# Design decisions

Short records of choices made while building, with the reason. The full plan lives in
the Bastion planning doc.

**OCSF as the event schema.** It's a published standard with a class for each event
type Bastion handles. Fields OCSF has no slot for go under `unmapped`, as the spec
recommends. Only the handful of classes in use are implemented (`src/bastion/ocsf.py`).

**Sigma rules, small in-process evaluator.** Rules are portable Sigma, so they can later
run in Wazuh or any SIEM unchanged. pySigma validates them in CI. bastiond evaluates the
subset it needs directly, because pySigma's backends compile to query languages, not
Python predicates.

**Redact before storing, not just before sending.** The local database only ever holds
redacted text. Process environment variables aren't even collected: the osquery query
leaves out `env`, and the normalizer masks it if it ever appears.

**Shadow mode is also the learning window.** The 14 days in which nothing is enforced is
when first-seen baselines are built. osquery's initial snapshot (counter 0) is never
alerted on.

**De-duplicate by subject, not pid.** The same rule firing on the same binary (and target)
within 60 seconds merges into one detection with a hit count. Re-running a script doesn't
produce ten alerts.

**Santa in Monitor mode, configured by profile.** The profile also turns on transitive
allowlisting with compiler rules for `ld` and `lipo`, so locally built binaries are
recorded as "built here" well before lockdown is considered. There's no rule for
`codesign`, per Santa's own warning.

**Our own osquery LaunchDaemon plist.** It points explicitly at our flag file, so the
running configuration is exactly what's in this repo.

**Public ntfy.sh for now, content-free pushes.** The iOS push spike needed a server before
the VM exists. Because ntfy.sh can read messages, pushes contain only rule titles and
counts. Phase 2 switches to self-hosted ntfy, reachable only over Tailscale.

**bastiond runs as root in Phase 1.** It's read-only and has to read root-owned sensor
logs. Phase 3 adds actions, and with them the privilege split from the plan: an
unprivileged detector and a minimal root executor.

**Unified log has no checkpoint.** `log stream` can't resume, so entries during downtime
are lost. Only low-value sources (sudo, Objective-See subsystems) use it; osquery and
Santa carry the important events durably.

## Phase 2

**bastiond serves a read-only edge API; the orchestrator runs in a container.** The
agents' code never runs as root or on the host. The API has fixed, typed queries and one
write (acknowledge a detection), so the worst a compromised or confused agent can do is
mislabel an incident. This is the read-only half of the plan's domain gateways; Phase 3
adds the action half behind Cedar policies.

**Detections are pulled, with acknowledgement after save.** The core polls the outbox
and acknowledges a detection only once its incident is stored. A crash means a
re-triage, never a lost detection. NATS replaces polling when the core moves to the VM.

**Routing and limits are code; judgment is the model's.** Which agent handles a
detection, the tool-round cap, spend caps and notification guardrails are plain Python.
Models decide only what the evidence means.

**The Warden model is skipped for confident benign findings.** Most detections on a
developer Mac are benign. Calling the larger model only when a finding is not a confident
benign keeps the cost near the small model's.

**The model provider sits behind one small interface.** Agents call `ModelClient`, so
another provider (the plan's options A and C) is one adapter, and tests run the real loop
with a scripted model.

**Trigger tests count as threats.** Agents are told to judge behavior, not names: a
"test" that performs an attack technique is reported like the technique. Otherwise an
attacker could name a payload `test`.

**Raw events keep 14 days, detections 90, incidents indefinitely.** Events also carry
indexed lookup columns (pid, parent pid, paths) so agent queries don't scan compressed
bodies.

**Phoenix for tracing, self-hosted.** One container instead of Langfuse's four, which
matters on a 16 GB Mac. Traces contain telemetry, so they never go to a hosted tracer.
