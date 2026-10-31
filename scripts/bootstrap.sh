#!/usr/bin/env bash
# Bastion Phase 0-1 setup for macOS on Apple Silicon.
#
# Installs the sensors (osquery, Santa in Monitor mode, LuLu, BlockBlock, KnockKnock),
# installs bastiond into /opt/bastion, writes configs, starts both LaunchDaemons, then
# runs the Phase 0 checks (test push, ~/.BrowserLock triage, posture report).
#
# Run as your normal user from the repo root:   ./scripts/bootstrap.sh
# It calls sudo itself. Safe to re-run: finished steps are skipped.
#
# Options:
#   --skip-tools     don't install/upgrade osquery, Santa or the Objective-See apps
#   --no-checks      skip the Phase 0 checks at the end
#   --dry-run        print what would run, change nothing

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=/opt/bastion
DATA="/Library/Application Support/Bastion"
LOGS=/Library/Logs/Bastion
REPORTS="$REPO/reports"
SKIP_TOOLS=0
NO_CHECKS=0
DRY=0

for arg in "$@"; do
  case "$arg" in
    --skip-tools) SKIP_TOOLS=1 ;;
    --no-checks) NO_CHECKS=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

STEP=0
step() { STEP=$((STEP + 1)); printf '\n\033[1m[%d] %s\033[0m\n' "$STEP" "$1"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m! %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
run()  { if [[ $DRY -eq 1 ]]; then printf '    + %s\n' "$*"; else "$@"; fi; }

# (Re)load a LaunchDaemon. bootout returns before the old job is fully gone, so an
# immediate bootstrap can fail with "5: Input/output error"; retry for a few seconds.
load_daemon() {
  local label="$1" plist="$2"
  run sudo launchctl bootout "system/$label" 2>/dev/null || true
  [[ $DRY -eq 1 ]] && { printf '    + sudo launchctl bootstrap system %s\n' "$plist"; return; }
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sudo launchctl bootstrap system "$plist" 2>/dev/null && { note "started $label"; return; }
    sleep 1
  done
  sudo launchctl bootstrap system "$plist" || die "couldn't start $label (see error above)"
}

# ---- preflight ---------------------------------------------------------------------
[[ "$(uname -s)" == Darwin ]] || die "Run this on your Mac."
[[ "$(uname -m)" == arm64 ]] || die "This script targets Apple Silicon."
[[ $EUID -ne 0 ]] || die "Run as your normal user, not with sudo (the script uses sudo itself)."
BREW="$(command -v brew || true)"
[[ -n "$BREW" ]] || die "Homebrew not found. Install it from https://brew.sh, then re-run."

echo "Bastion setup — repo: $REPO"
echo "You'll be asked for your password once. Approval prompts in System Settings come at the end."
run sudo -v
# keep sudo alive for the duration of the script
if [[ $DRY -eq 0 ]]; then
  ( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
fi

# Download the latest GitHub release asset matching a regex, verify signature and
# notarization, then install it. Falls back to a Homebrew cask if the API lookup fails.
install_github_pkg() {
  local repo="$1" pattern="$2" name="$3" cask="$4"
  local url tmp sig gk
  url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | grep -Eo '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 \
        | grep -E "$pattern" | head -1 || true)"
  if [[ -z "$url" ]]; then
    warn "Couldn't find a $name package on GitHub; falling back to Homebrew cask '$cask'."
    run "$BREW" install --cask "$cask"
    return
  fi
  note "Downloading $url"
  tmp="$(mktemp -d)"
  run curl -fL --progress-bar -o "$tmp/$name.pkg" "$url"
  if [[ $DRY -eq 0 ]]; then
    sig="$(pkgutil --check-signature "$tmp/$name.pkg" || true)"
    grep -q "signed by a developer certificate issued by Apple for distribution" <<<"$sig" \
      || die "$name package signature check failed: $sig"
    note "Signed by: $(sed -n 's/^ *1\. //p' <<<"$sig" | head -1)"
    gk="$(spctl -a -vv -t install "$tmp/$name.pkg" 2>&1 || true)"
    grep -q accepted <<<"$gk" \
      || die "$name package is not notarized by Apple; refusing to install: $gk"
  fi
  run sudo installer -pkg "$tmp/$name.pkg" -target /
}

# ---- 1. tools ------------------------------------------------------------------------
step "Install sensors and tools"
if [[ $SKIP_TOOLS -eq 1 ]]; then
  note "skipped (--skip-tools)"
else
  "$BREW" list uv >/dev/null 2>&1 || run "$BREW" install uv
  for cask in lulu blockblock knockknock; do
    if "$BREW" list --cask "$cask" >/dev/null 2>&1; then note "$cask already installed"
    else run "$BREW" install --cask "$cask"; fi
  done
  if [[ -d /opt/osquery/lib/osquery.app ]]; then note "osquery already installed"
  else install_github_pkg osquery/osquery 'osquery-[0-9.]+\.pkg$' osquery osquery; fi
  if [[ -d /Applications/Santa.app ]]; then note "Santa already installed"
  else install_github_pkg northpolesec/santa 'santa-[0-9.]+\.pkg$' santa santa; fi
fi
UV="$(command -v uv || echo /opt/homebrew/bin/uv)"
[[ -x "$UV" || $DRY -eq 1 ]] || die "uv not found (install with: brew install uv)"

# ---- 2. bastion package ---------------------------------------------------------------
step "Install Bastion into $PREFIX"
run sudo mkdir -p "$PREFIX" "$DATA" "$LOGS"
run sudo chmod 700 "$DATA"
run sudo env UV_PYTHON_INSTALL_DIR="$PREFIX/python" UV_CACHE_DIR="$PREFIX/.uv-cache" \
  "$UV" venv --quiet --allow-existing --python 3.12 "$PREFIX/venv"
run sudo env UV_CACHE_DIR="$PREFIX/.uv-cache" \
  "$UV" pip install --quiet --python "$PREFIX/venv/bin/python" --reinstall-package bastion "$REPO"
run sudo mkdir -p /usr/local/bin
run sudo ln -sf "$PREFIX/venv/bin/bastion" /usr/local/bin/bastion
note "bastion CLI linked at /usr/local/bin/bastion"

# ---- 3. configuration -----------------------------------------------------------------
step "Write configuration"
CONF="$DATA/config.toml"
if sudo test -f "$CONF"; then
  note "keeping existing $CONF"
else
  # openssl, not `tr </dev/urandom | head`: under pipefail that pipeline exits 141 (SIGPIPE)
  TOPIC="bastion-$(openssl rand -hex 12)"
  if [[ $DRY -eq 0 ]]; then
    sed "s/__NTFY_TOPIC__/$TOPIC/" "$REPO/config/config.toml.template" \
      | sudo tee "$CONF" >/dev/null
  fi
  run sudo chmod 600 "$CONF"
  note "created $CONF with a random ntfy topic"
fi
TOPIC="$(sudo sed -n 's/^ntfy_topic *= *"\(.*\)"/\1/p' "$CONF" 2>/dev/null || true)"

# ---- 4. osquery -----------------------------------------------------------------------
step "Configure and start osquery"
run sudo mkdir -p /var/osquery /var/log/osquery
run sudo install -m 644 "$REPO/config/osquery/osquery.conf" /var/osquery/osquery.conf
run sudo install -m 644 "$REPO/config/osquery/osquery.flags" /var/osquery/osquery.flags
run sudo install -m 644 "$REPO/config/launchd/io.osquery.agent.plist" \
  /Library/LaunchDaemons/io.osquery.agent.plist
load_daemon io.osquery.agent /Library/LaunchDaemons/io.osquery.agent.plist

# ---- 5. bastiond ----------------------------------------------------------------------
step "Start bastiond (shadow mode: observe and record only)"
run sudo install -m 644 "$REPO/config/launchd/com.bastion.bastiond.plist" \
  /Library/LaunchDaemons/com.bastion.bastiond.plist
load_daemon com.bastion.bastiond /Library/LaunchDaemons/com.bastion.bastiond.plist

# ---- 6. approvals ---------------------------------------------------------------------
step "Approvals only you can click"
cat <<EOF
    macOS requires you to approve these yourself. Do them now, in this order:

    a) Santa profile (Monitor mode + compiler rules for your builds):
         Double-click opens below -> System Settings > General > Device Management -> Install
    b) System extensions: System Settings > General > Login Items & Extensions
         -> Endpoint Security Extensions: turn ON Santa and BlockBlock
         -> Network Extensions: turn ON LuLu
       Open LuLu and BlockBlock once from /Applications so they finish installing.
       Tip: in LuLu's settings, enable Passive mode for the shadow week (no pop-ups).
    c) Full Disk Access: System Settings > Privacy & Security > Full Disk Access, turn ON:
         - osqueryd   (/opt/osquery/lib/osquery.app — use + and Cmd-Shift-G to find it)
         - Santa / santad (usually listed after step b)
         - BlockBlock
         - your terminal app (only needed for the TCC part of 'bastion posture')
       (The script restarts osquery for you when you press Return.)
    d) iPhone: install the "ntfy" app, add a subscription to server ntfy.sh, topic:
         ${TOPIC:-<see notify.ntfy_topic in $CONF>}
EOF
if [[ $DRY -eq 0 ]]; then
  open "$REPO/config/santa/bastion-santa.mobileconfig" || true
  open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2>/dev/null || true
fi
if [[ -t 0 && $DRY -eq 0 ]]; then
  read -r -p "    Press Return when you've done a-d (or Ctrl-C to finish later)... " _
fi
# osqueryd only picks up a new Full Disk Access grant when it restarts.
run sudo launchctl kickstart -k system/io.osquery.agent || warn "couldn't restart osquery"

# ---- 7. phase 0 checks ----------------------------------------------------------------
if [[ $NO_CHECKS -eq 0 ]]; then
  step "Phase 0 checks"
  run mkdir -p "$REPORTS"
  note "Test push (check your phone):"
  run sudo /usr/local/bin/bastion test-push || warn "push failed; see message above"
  note "Who owns ~/.BrowserLock?"
  if [[ $DRY -eq 0 ]]; then
    # shellcheck disable=SC2024  # the report is meant to be written as you, not root
    sudo /usr/local/bin/bastion whoowns "$HOME/.BrowserLock" > "$REPORTS/browserlock.md" \
      && note "saved $REPORTS/browserlock.md" && tail -3 "$REPORTS/browserlock.md" | sed 's/^/    /'
  fi
  note "Posture checks (takes ~1 minute; software update check is the slow part):"
  run sudo /usr/local/bin/bastion posture --out "$REPORTS" >/dev/null \
    && note "saved posture report in $REPORTS"
  run sudo chown -R "$USER" "$REPORTS"
  note "Sensor health:"
  run sudo /usr/local/bin/bastion doctor || warn "some sensors need attention; follow the fixes above"
fi

step "Done"
cat <<EOF
    Bastion is running in shadow mode. Nothing is blocked; detections are recorded.
    Daily summary push: 08:30. Useful commands:
      sudo bastion status      # heartbeat, sensors, 24 h counts
      sudo bastion doctor      # sensor health with exact fixes
      sudo bastion report      # false-positive review (the Phase 1 gate, after ~7 days)
    Logs: $LOGS/bastiond.log   Data: $DATA
    Reports (not committed to git): $REPORTS
EOF
