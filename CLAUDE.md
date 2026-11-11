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
- Only `src/bastion/executor` changes the system. Its actions are the fixed, typed set in
  `executor/actions.py` (tier 1 reversible, tier 2 permanent). Don't add kill, block or
  free-form delete, and don't add an action without an undo (tier 1) or an approval (tier 2),
  a Cedar rule in `policy/`, and tests for both.
- The executor runs a command only if it is signed by the gateway key, and re-validates every
  target itself. Tier 2 and anything non-automatic waits for a passkey. Shadow mode is the
  default; only the root CLI (`bastion autonomy`) switches it. Never add an HTTP path that
  changes the mode, skips the signature or approves without a passkey.
- Action targets come from the detection (`core/playbook.py`), never from model output.
- The orchestrator (`src/bastion/core`) reaches the Mac only through `edge_api.py`. Queries
  stay read-only, typed and bounded: no free-form queries. The only writes are acknowledging
  a detection and the `/v1/exec/*` routes, which hand off to the executor.
- The signing key lives only in the gateway container (`deploy/.env.gateway`). Core and web
  never get it; web never gets the model API key.
- Agents return Pydantic models (`core/schemas.py`), never free text. Limits (tool rounds, spend
  caps, routing, notification guardrails) are enforced in code, not in prompts. Telemetry given
  to a model is wrapped with `untrusted(...)`.
- Core tests use `ScriptedClient` and `LocalEdge`; never call a real model in tests.
- Keep anything from Colin's previous employer out of this repo: no internal names, code or vendor
  lists.
- Log every bug, misfire or install surprise in `docs/issues-log.md` (symptom, cause, fix,
  commit, test), newest first, and add it to the index table. Update the entry if a fix
  changes later.
