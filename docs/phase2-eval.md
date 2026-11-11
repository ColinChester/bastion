# Phase 2 evaluation

Gate: *every rule hit produces a correct structured finding on the labeled set.* The
labeled set is `tests/labeled_events/phase1-labels.yml` (24 labels); `bastion-core eval`
triages up to two recent detections per label with the real models and grades each.

Models: agents `claude-haiku-5-5`, Warden `claude-sonnet-5-5`.

| Run | Correct | Missed threats | False alarms | Inconclusive | Errors | Spend |
| --- | --- | --- | --- | --- | --- | --- |
| Nov 11, 14:34 | 14 / 46 | 28 | 0 | 4 | 0 | $0.60 |
| Nov 11, 14:59 | **45 / 46** | **0** | **0** | 1 | 0 | $0.69 |

(An earlier attempt at 14:0x crashed on Warden's first call; issues log #31.)

## Run 1: agents explained attacks away

All 28 misses were trigger-test detections called benign, because the agents saw that
Colin's test script started them. That's a bypass, since pasted-command attacks also
start from the user's terminal. The fix moved the rule into code: a benign verdict must
rest on what the software *is* (macOS component, signed vendor software, developer
toolchain), otherwise it becomes suspicious (issues log #32).

## Run 2: gate met, with one inconclusive

- Every trigger test was flagged suspicious, typically at 50–80% confidence, with
  summaries that name the technique and note it came from Bastion's test script.
- Every shadow-week false positive was called benign with the right reason: GitHub CLI's
  credential helper, Safari's import service, GoogleUpdater and Mozilla's updater
  (identified by their signing teams), the .NET compiler, OrbStack's helper and
  Tailscale as new login items.
- `bootstrap-restart-osquery` was flagged suspicious: the genuine `launchctl` stopped
  osquery and no record shows who ran it.
- The one inconclusive: **zoom-updater-plist** (40%). The stored detection came from
  FSEvents, which doesn't record which process wrote the file. A detection that merges an
  FSEvents and an Endpoint Security copy of the same write now keeps the copy that names
  the writer (issues log #33).

**Cost.** $0.69 for 46 detections is about **$0.015 per detection**, higher than the
$0.006 estimated earlier, because agents made 2–10 tool calls and Warden reviewed every
flagged case. At 5–25 detections a day that's roughly **$2–11 a month**, still under the
$25 cap.

## Re-running

```bash
./scripts/test-triggers.sh   # fresh true positives
docker compose -f deploy/docker-compose.yml exec core bastion-core eval
docker compose -f deploy/docker-compose.yml cp core:/data/ reports/core-data/   # full reports
```
