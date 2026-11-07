# Phase 0–1 setup checklist

Everything Claude could build without your Mac is in this repo. These are the steps that
need you: your password, clicks in System Settings, or accounts. Expect about 30 minutes,
plus 15 for the Oracle VM.

## 1. Run the setup script (about 15 minutes)

```bash
mkdir -p ~/git && cd ~/git
git clone https://github.com/ColinChester/bastion.git
cd bastion
./scripts/bootstrap.sh
```

It asks for your password at the start, and again during the BlockBlock install (its
Homebrew installer prompts separately). Then it pauses at **step 6** for the approvals
below. Use `--dry-run` first if you want to see every command before anything runs.

## 2. Approvals (the script opens the right panes)

- [ ] **Santa profile**: System Settings → **Profile Downloaded** (in the sidebar under your name) → *Bastion: Santa Configuration* → Install
- [ ] **System extensions**: General → Login Items & Extensions
  - Endpoint Security Extensions: **Santa**, **BlockBlock** on
  - Network Extensions: **LuLu** on
- [ ] Open **LuLu** and **BlockBlock** once from /Applications to finish their setup. In LuLu's settings, turn on **Passive mode** for the shadow week so it doesn't prompt for every connection.
- [ ] **Full Disk Access** (Privacy & Security → Full Disk Access): `osqueryd` (at `/opt/osquery/lib/osquery.app`), Santa, BlockBlock, and your terminal app
- [ ] **iPhone**: install **ntfy**, subscribe to server `ntfy.sh` and the topic the script prints

Then press Return in the script. It restarts osquery so Full Disk Access takes effect,
then runs the Phase 0 checks.

## 3. Check it worked

- [ ] Test push arrived on your phone
- [ ] `sudo bastion doctor` shows **OK** for osquery, santa, bastiond, notify. If osquery
      says "no process events", Full Disk Access isn't active yet: check the grant, then run
      `sudo launchctl kickstart -k system/io.osquery.agent`.
- [ ] Read `reports/browserlock.md` and note who owns `~/.BrowserLock`
- [ ] Read `reports/posture-*.md` and fix anything marked **FAIL**
- [ ] A minute later, `sudo bastion status` shows event counts going up for osquery and santa.
- [ ] Optional smoke test (harmless: curl's output goes to /dev/null, so sh gets nothing):
      `curl -s -o /dev/null https://example.com | sh`. Within a minute
      `sudo bastion report --days 1` lists *Download piped into a shell (interactive)*.

## 4. Oracle VM (Phase 0, can be done separately)

Follow [oracle-vm.md](oracle-vm.md). It takes about 15 minutes if capacity is available.

## 5. Spend alert (when you create model API keys in Phase 2)

Phases 0–1 make no model calls, so there's nothing to cap yet. When you create Anthropic
or OpenAI keys in Phase 2, set a $25/month spend alert in each provider console.

## 6. The shadow week (Phase 1 gate)

- [ ] Use the Mac normally for 7 days. You'll get one quiet summary push each morning at 08:30.
- [ ] Day 7: `./scripts/test-triggers.sh` fires every detection once with harmless decoys
      and checks each was recorded (about 7 minutes; BlockBlock will ask about a test
      plist, which is expected). Its PASS lines are the labeled true positives.
- [ ] Day 7: `sudo bastion report --out reports/fp-review.md`, tick **benign** or **real**
      for each subject, and add filters for the benign ones (see
      [detections.md](detections.md#tuning)). That reviewed list is the Phase 1 gate.

If anything fails, `sudo bastion doctor` prints the exact fix. Logs are in
`/Library/Logs/Bastion/bastiond.log`.
