# Issues log

A running record of the problems hit while building and running Bastion, what caused
them, and how they were fixed. Newest first. Add an entry whenever something breaks,
misfires or surprises us, even if the fix is "documented, working as intended".

Each entry: **Symptom** (what we saw), **Cause**, **Fix**, and where the fix landed.
Status is one of: fixed, mitigated, documented, open.

| # | Date | Area | Issue | Status |
| --- | --- | --- | --- | --- |
| 23 | 2026-11-10 | CI | GitHub Actions blocked by an account billing lock | open |
| 22 | 2026-11-10 | Process | A failed CI run was reported as passing | fixed |
| 21 | 2026-11-01 | Detection | Existing login items alerted as new (69 hits) | fixed |
| 20 | 2026-11-01 | Detection | GitHub CLI token reads tripped the keychain rule (55 hits) | fixed |
| 19 | 2026-11-01 | Detection | Listener baseline ballooned to 1,239 entries | fixed |
| 18 | 2026-11-01 | Detection | Setup script trips the security-tool tampering rule | documented |
| 17 | 2026-10-31 | CLI | `bastion report` without sudo crashed with a traceback | fixed |
| 16 | 2026-10-31 | CLI | Reports written under sudo were owned by root | fixed |
| 15 | 2026-10-31 | Daemon | A crashed collector would go unnoticed | fixed |
| 14 | 2026-10-31 | Doctor | `doctor` checked processes, not whether events arrived | fixed |
| 13 | 2026-10-31 | Detection | First batch of exec events skipped as a "snapshot" | fixed |
| 12 | 2026-10-31 | Detection | Same file write produced two detections | fixed |
| 11 | 2026-10-31 | Detection | Credential rule would fire on browsers and our own tools | fixed |
| 10 | 2026-10-31 | Collectors | Very long log lines could crash or stall readers | fixed |
| 9 | 2026-10-31 | Posture | Codex's own sign-in file flagged as a leaked secret | fixed |
| 8 | 2026-10-31 | Install | iTerm's Full Disk Access needs an iTerm restart | documented |
| 7 | 2026-10-31 | Install | osquery didn't pick up Full Disk Access until restarted | fixed |
| 6 | 2026-10-31 | Install | BlockBlock's installer asks for the password again | documented |
| 5 | 2026-10-31 | Install | Restarting a LaunchDaemon could fail with error 5 | fixed |
| 4 | 2026-10-31 | Install | Random topic generation would abort the setup script | fixed |
| 3 | 2026-10-31 | Detection | Interactive `curl … \| sh` was invisible to the Sigma rule | fixed |
| 2 | 2026-10-31 | Build | GitHub API unreachable when resolving sensor packages | mitigated |
| 1 | 2026-10-31 | Build | Small build and test failures during development | fixed |

---

## 23. GitHub Actions blocked by an account billing lock

**Symptom.** The CI run for `b6d5035` failed in 2 seconds with no logs.

**Cause.** GitHub refused to start the job: "The job was not started because your account
is locked due to a billing issue." The code itself is fine. Running the same CI steps
(ruff, pytest, `bastion rules`, shellcheck) on a clean clone passes: 114 tests, 15 rules,
0 errors.

**Fix.** Needs Colin: resolve the billing issue under GitHub Settings → Billing and plans,
then re-run the failed workflow. Public repos don't use paid Actions minutes, but a
locked account can't start any jobs. Until then, run the CI steps locally before pushing.

## 22. A failed CI run was reported as passing

**Symptom.** On Nov 7, Claude reported CI as passing for `b6d5035`, but that run had
failed (#23).

**Cause.** The wait loop read "the newest run" a few seconds after pushing, before GitHub
had registered the new run, so it checked the previous commit's successful run.

**Fix.** Look up the run for the pushed commit's SHA (`gh run list --commit <sha>`) and
wait for that one, retrying until it exists.

## 21. Existing login items alerted as new (69 hits)

**Symptom.** The first day's review showed 69 *New LaunchAgent, LaunchDaemon or Login
Item* hits for apps that had been installed for months (Zoom, BlueStacks, Raycast,
Parallels…), some several times.

**Cause.** osquery's first scheduled run took its snapshot before Full Disk Access was
granted, so it couldn't see most background items. Once access was granted, everything
it could now see came through as "added" with a non-zero counter, which Bastion treated
as genuinely new. Volatile columns in the queries (`status`, `disabled`, `keep_alive`)
could also make an unchanged item reappear.

**Fix.**
- Bastion remembers every launch item it has ever seen (baseline kind `persistence`) and
  marks re-reported ones `SeenBefore`; the rule filters those out.
- The `launchd` and `startup_items` queries select identity columns only.
- On a first install, `bootstrap.sh` clears osquery's saved results after the approvals
  step, so its first real snapshot happens with Full Disk Access.

Commit `1c150ab`. Tests: `test_known_launch_item_reported_again_does_not_alert`.

## 20. GitHub CLI token reads tripped the keychain rule (55 hits)

**Symptom.** *Keychain Secrets Read With the security CLI* fired 55 times on
`security find-generic-password -s gh:github.com -wa ColinChester`.

**Cause.** The GitHub CLI stores its token in the keychain and reads it with the
`security` command on every git push or pull. That's legitimate, but it looks exactly
like what credential stealers do.

**Fix.** A narrow filter: the parent process is `gh` **and** the service name starts
with `gh:`. Any other program reading keychain secrets still alerts.

Commit `1c150ab`. Test: `test_gh_cli_keychain_read_is_filtered`.

## 19. Listener baseline ballooned to 1,239 entries

**Symptom.** After one day the first-seen listener baseline held 1,239 keys. Once the
14-day learning window ended, every new key would have alerted.

**Cause.** The query included UDP sockets, and the key was binary + port. Unconnected
UDP sockets (QUIC, mDNS) and services like `rapportd` pick a random port each time, so
the keys never repeat.

**Fix.** Query TCP listeners only and skip loopback addresses. Ports in the ephemeral
range (49152 and up) collapse to one `ephemeral` key per binary.

Commit `1c150ab`. Test: `test_ephemeral_and_loopback_listeners_share_one_baseline_key`.

## 18. Setup script trips the security-tool tampering rule

**Symptom.** *Attempt to Stop or Unload a Security Tool* fires on
`launchctl bootout system/io.osquery.agent`.

**Cause.** `bootstrap.sh` restarts osquery and bastiond with `launchctl bootout`, which
is exactly what the rule watches for.

**Fix.** None needed; that's the rule working. Documented in
[detections.md](detections.md#tuning) so these hits get marked benign when they line up
with a reinstall.

## 17. `bastion report` without sudo crashed with a traceback

**Symptom.** `bastion report --out reports/fp-review.md` printed a Python
`PermissionError` traceback for `/Library/Application Support/Bastion/config.toml`.

**Cause.** The data folder is root-only on purpose. `load_config` let the error from
`Path.is_file()` escape instead of explaining it.

**Fix.** The CLI says the command needs `sudo` and exits cleanly. Commands that don't
need Bastion's data (`rules`, `posture`, `whoowns`, `replay`) fall back to defaults and
work without sudo.

Commit `ebe6ca0`. Tests: `test_cli_without_sudo_explains_instead_of_crashing`,
`test_cli_rules_works_without_sudo`.

## 16. Reports written under sudo were owned by root

**Symptom.** Report files created with `sudo bastion report --out …` inside the repo were
owned by root.

**Fix.** When run under sudo, report and posture files are chowned back to `SUDO_UID`
and `SUDO_GID`.

Commit `ebe6ca0`. Test: `test_report_file_is_handed_back_to_sudo_user`.

## 15. A crashed collector would go unnoticed

**Symptom.** Found in code review: if the osquery, Santa or unified-log reader task
raised, bastiond kept running with a fresh heartbeat while that sensor's events were
silently dropped.

**Fix.** bastiond waits on all its tasks; if any one ends, it logs the exception and
exits non-zero so launchd's KeepAlive restarts it.

Commit `ebe6ca0`. Test: `test_daemon_exits_nonzero_when_a_collector_crashes`.

## 14. `doctor` checked processes, not whether events arrived

**Symptom.** `doctor` reported OK as long as the processes existed, even if their events
never reached bastiond (wrong log path, crashed reader, missing permission).

**Fix.** `doctor` also checks bastiond's heartbeat and when the last osquery and Santa
event reached it (`osquery feed`, `santa feed`).

Commit `ebe6ca0`. Tests: `test_doctor_ingest_checks`, `test_doctor_flags_stale_heartbeat`.

## 13. First batch of exec events skipped as a "snapshot"

**Symptom.** Found in code review: the first batch of process and file events after
install was flagged `initial_snapshot` and never evaluated.

**Cause.** The counter-0 exemption was applied to every osquery query. It only makes
sense for state queries (launch items, apps), whose first result is a backlog of
existing things. Event tables have no backlog.

**Fix.** The exemption applies only to state queries.

Commit `ebe6ca0`. Tests: `test_first_exec_batch_is_evaluated_not_treated_as_snapshot`,
`test_state_query_snapshot_still_skipped`.

## 12. Same file write produced two detections

**Symptom.** Found in code review: writing a LaunchAgent plist created two detections.

**Cause.** Both Endpoint Security (with the writing process) and FSEvents (without one)
report the write, and the de-duplication key included the process.

**Fix.** File detections are de-duplicated by file path alone.

Commit `ebe6ca0`. Test: `test_same_file_write_from_es_and_fsevents_merges`.

## 11. Credential rule would fire on browsers and our own tools

**Symptom.** Found in code review: *Credential Store Opened by an Unexpected Process*
would fire on Chrome helper processes (Renderer, GPU, Plugin), on osquery hashing
watched files, and on Bastion's own posture check reading `~/.aws`.

**Fix.** Filters for Chrome helper variants, the Firefox bundle, `/opt/osquery/`,
`/opt/bastion/` and Santa.

Commit `ebe6ca0`. Test: `test_credential_rule_ignores_browsers_and_own_tools`.

## 10. Very long log lines could crash or stall readers

**Symptom.** Found in code review: a unified-log entry over 64 KB would crash that
reader, and a log line longer than the 8 MB read cap would stall the file tailer forever.

**Fix.** A 4 MB line limit for `log stream`, with oversized lines skipped. The tailer
skips a line longer than its cap, up to the next newline. `log stream` is also
terminated cleanly on shutdown.

Commit `ebe6ca0`. Test: `test_tailer_skips_a_line_longer_than_the_read_cap`.

## 9. Codex's own sign-in file flagged as a leaked secret

**Symptom.** The posture report listed two "plaintext secrets" in `~/.codex/auth.json`.

**Cause.** That's where the Codex CLI deliberately stores its sign-in tokens. Tokens
there are expected; the real risk is other users being able to read the file.

**Fix.** Tool-managed token files are flagged only if group- or world-readable, with a
`chmod 600` fix.

Commit `ebe6ca0`. Test: `test_tool_token_files_flagged_only_when_readable_by_others`.

## 8. iTerm's Full Disk Access needs an iTerm restart

**Symptom.** After granting iTerm Full Disk Access, the posture report's privacy-grants
check still couldn't read the TCC databases.

**Cause.** macOS applies a new Full Disk Access grant only when the app relaunches.

**Fix.** Quit and reopen iTerm, then re-run `sudo bastion posture --out reports`. Only
that one check is affected.

## 7. osquery didn't pick up Full Disk Access until restarted

**Symptom.** After the approvals step, osquery kept running without Full Disk Access.

**Cause.** osqueryd reads its permissions at launch.

**Fix.** `bootstrap.sh` restarts osquery right after the approvals step (on a first
install it also clears pre-access results; see #21). Commit `17c1378`.

## 6. BlockBlock's installer asks for the password again

**Symptom.** Midway through step 1, the script stopped at a second `Password:` prompt.

**Cause.** BlockBlock's Homebrew cask runs its own installer through sudo, which doesn't
reuse the script's sudo session.

**Fix.** Documented in [setup-checklist.md](setup-checklist.md). Commit `17c1378`.

## 5. Restarting a LaunchDaemon could fail with error 5

**Symptom.** Found in a dry run: `launchctl bootout` returns before the old job is fully
gone, so an immediate `launchctl bootstrap` can fail with "5: Input/output error" and
abort the script.

**Fix.** A `load_daemon` helper retries the bootstrap for up to 10 seconds. Commit
`5406bb6`.

## 4. Random topic generation would abort the setup script

**Symptom.** Found in a dry run: `tr -dc … </dev/urandom | head -c 24` exits with 141
(SIGPIPE) under `set -o pipefail`, which kills the script at the config step.

**Fix.** The topic is generated with `openssl rand -hex 12`. The Gatekeeper check was
changed for the same reason: its output is captured first instead of piped into
`grep -q`. Commit `5406bb6`.

## 3. Interactive `curl … | sh` was invisible to the Sigma rule

**Symptom.** Found in review: the *Download Piped Into a Shell* rule could never match
the pipe typed into Terminal.

**Cause.** The shell starts `curl` and `sh` as two sibling processes. Neither command
line contains the `|`, so a single-event rule can't see it.

**Fix.** A correlation analytic (`bastion-fetch-piped-to-shell`) fires when curl or wget
and a stdin-reading shell are started by the same parent within 3 seconds. The Sigma
rule still covers single command lines (`sh -c`, osascript, LaunchAgents). Commit
`5406bb6`.

## 2. GitHub API unreachable when resolving sensor packages

**Symptom.** From the build environment, the GitHub API returned 403, so the latest
osquery and Santa release assets couldn't be looked up ahead of time.

**Fix.** `bootstrap.sh` resolves the latest release on the Mac at install time, checks
the package signature and notarization, and falls back to the Homebrew cask if the
lookup fails. Commit `5406bb6`.

## 1. Small build and test failures during development

- The hatchling build failed with "Readme file does not exist". Fixed by adding `README.md`.
- An osquery record with `columns: null` produced an empty exec event. Fixed: the
  normalizer drops exec records without a path.
- pytest-asyncio's loop-scope deprecation warning. Fixed by setting
  `asyncio_default_fixture_loop_scope`.

All in commit `5406bb6`.
