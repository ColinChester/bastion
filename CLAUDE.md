# Bastion: notes for coding agents

- Python 3.12, src layout (`src/bastion`). Run `.venv/bin/pytest -q` and `.venv/bin/ruff check .`
  before committing; both must pass.
- Events are OCSF dicts built with the helpers in `src/bastion/ocsf.py`. Fields with no OCSF slot go
  under `unmapped`.
- Redaction happens in the pipeline before storage (`daemon.Pipeline.handle`). Never add a code path
  that stores or sends unredacted event text, and never put paths or command lines in push
  notifications.
- Sigma rules live in `rules/<category>/`. Every new rule needs a positive and a benign case in
  `tests/test_rules.py`, and must use only fields in `detect/fields.py` (or dotted OCSF paths).
- Anything that runs macOS commands goes through `macos.Runner` so tests can fake it.
- Everything is observe-only through Phase 2. Don't add actions that change the system (kill,
  quarantine, block) until Phase 3's policy engine and root executor exist.
- The orchestrator (`src/bastion/core`) reaches the Mac only through `edge_api.py`. Keep that API
  read-only, typed and bounded: no free-form queries, and no new write besides acknowledging a
  detection.
- Agents return Pydantic models (`core/schemas.py`), never free text. Limits (tool rounds, spend
  caps, routing, notification guardrails) are enforced in code, not in prompts. Telemetry given
  to a model is wrapped with `untrusted(...)`.
- Core tests use `ScriptedClient` and `LocalEdge`; never call a real model in tests.
- Keep anything from Colin's previous employer out of this repo: no internal names, code or vendor
  lists.
- Log every bug, misfire or install surprise in `docs/issues-log.md` (symptom, cause, fix,
  commit, test), newest first, and add it to the index table. Update the entry if a fix
  changes later.
