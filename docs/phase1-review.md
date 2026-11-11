# Phase 1 review: shadow week, Oct 31 – Nov 11, 2026

The Phase 1 gate is one week of events with a reviewed false-positive list. This is that
list. Every distinct subject the detections raised during the shadow period is
classified below, with what was done about it. It also serves as the labeled set for
Phase 2: the orchestrator's findings will be checked against these labels.

**Volume:** 434,334 osquery events, 407,171 Santa events and 1,791 unified-log events.
Detections: 2,631 hits across 838 distinct detections and 15 rules, plus 126 hits in the
first day's review (Nov 1).

## True positives (trigger test)

`scripts/test-triggers.sh` fired every detection with harmless decoys on Nov 11:
- **First run:** 14 of 16 detected. The two file rules missed because of how osquery
  watches files (see the issues log, #24); the script now accounts for that.
- **Second run:** see the result recorded at the end of this page.

| Detection | Decoy that triggered it |
| --- | --- |
| Gatekeeper Disabled With spctl | `build/decoys/spctl --master-disable` |
| Keychain Secrets Read With the security CLI | `build/decoys/security find-generic-password -s bastion-test -w` |
| AppleScript Dialog Asking for a Password | `build/decoys/osascript -e 'display dialog … with hidden answer'` |
| Local Account Created or Added to the Admin Group | `build/decoys/sysadminctl -addUser bastiontest` |
| Privacy Permission (TCC) Database Tampering | `build/decoys/tccutil reset All com.bastiontest.decoy` |
| Quarantine Attribute Removed From a File | `build/decoys/xattr -d com.apple.quarantine …` |
| Attempt to Stop or Unload a Security Tool | `build/decoys/launchctl bootout system/com.bastiontest.notreal` |
| Download Piped Into a Shell | `sh -c "…/curl -s https://example.invalid \| sh"` |
| Download piped into a shell (interactive) | `…/curl -s https://example.invalid \| sh` |
| Execution From a Temporary or Shared Folder | ad-hoc signed copy of `true` in `/private/tmp` |
| Binary Executed From a Hidden Folder in the Home Directory | ad-hoc signed copy in `~/.bastion-test/` |
| Unsigned or Ad-hoc Signed Binary Run From a Download Folder | ad-hoc signed copy in `~/Downloads/` |
| Credential Store Opened by an Unexpected Process | decoy `reader` opening `~/.ssh/id_bastion_test` |
| Shell Startup File Modified | append to a new `~/.zlogin` |
| LaunchAgent or LaunchDaemon Property List Written | `~/Library/LaunchAgents/com.bastiontest.decoy.plist` |
| New LaunchAgent, LaunchDaemon or Login Item | the same plist, seen by osquery's launchd scan |

## False positives

| Rule | Subject | Hits | Cause | Resolution |
| --- | --- | --- | --- | --- |
| Keychain Secrets Read | `security find-generic-password -s gh:github.com -wa ColinChester` | 2,642 | GitHub CLI reading its own token. Claude Code runs `gh auth token` and `gh issue list` in the background, and git calls `gh auth git-credential get` | Filter on parent `gh` plus the `gh:` service. Parent resolution fixed (#20, #26) |
| New LaunchAgent, LaunchDaemon or Login Item | 69 existing login items (Zoom, BlueStacks, Raycast, Parallels…) | 69 | osquery's first snapshot ran before Full Disk Access | Seen-before baseline, stable query columns, osquery state reset on fresh install (#21) |
| New LaunchAgent, LaunchDaemon or Login Item | `/Applications/Microsoft Outlook.app` | 1 | Outlook came back as a login item after being in the Trash on Oct 31 (reinstalled or restored) | None needed: a genuine new login item, correctly reported once |
| Attempt to Stop or Unload a Security Tool | `launchctl bootout system/io.osquery.agent` | 4 | `bootstrap.sh` restarting osquery during reinstalls | Expected; documented in detections.md (#18) |
| Credential Store Opened | Safari's `BrowserDataImportingService` opening Chrome `Login Data` and Firefox `logins.json` | 3 | Safari's built-in "import from another browser" service | Filter on its exact system path (#25) |
| Quarantine Attribute Removed | `xattr -d -r com.apple.quarantine "/Applications/Google Chrome.app"` | 4 | GoogleUpdater's `.keystone_install` script after each Chrome update | Filter on that parent script and Chrome's path (#28) |
| Quarantine Attribute Removed | `xattr -dr com.apple.quarantine /Applications/Firefox.app` | 3 | Firefox's own updater (`org.mozilla.updater`) | Filter on the updater and Firefox's path (#28) |
| Binary Executed From a Hidden Folder | `~/.nuget/packages/…/ilc` | 4 | .NET NativeAOT compiler during a local build | Filter `~/.nuget/packages/` (#25) |
| LaunchAgent or LaunchDaemon Property List Written | `us.zoom.updater.gui.501.app.terminate.update.plist` | 2 | Zoom's updater | Filter `us.zoom.updater.` (#25) |

No detection during the shadow period was a real threat.

## Gate

- [x] A week or more of events from all three sensors (osquery, Santa, unified log),
  with `doctor` reporting every component and feed healthy.
- [x] Every distinct subject reviewed and classified above; each benign pattern has a
  filter and a regression test.
- [ ] Trigger test re-run with all 16 detections passing after the fixes. (Result
  recorded here when run.)
