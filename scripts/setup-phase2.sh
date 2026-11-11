#!/usr/bin/env bash
# Bastion Phase 2 setup: the orchestrator, agents, incident page, ntfy and tracing.
#
# Safe to re-run. It:
#   1. installs OrbStack (containers) if Docker isn't available
#   2. updates bastiond and turns on its local, read-only edge API
#   3. writes deploy/.env (asks you to paste your Anthropic API key; it is not shown)
#   4. builds and starts the containers
#   5. exposes the incident page and ntfy to your tailnet with Tailscale Serve
#   6. runs `bastion-core check`
#
#   ./scripts/setup-phase2.sh            full setup
#   ./scripts/setup-phase2.sh --no-update  skip reinstalling bastiond
set -euo pipefail

UPDATE=1
[[ "${1:-}" == "--no-update" ]] && UPDATE=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENVF="$REPO/deploy/.env"
COMPOSE=(docker compose -f "$REPO/deploy/docker-compose.yml")
STEP=0

step() { STEP=$((STEP + 1)); printf '\n\033[1m[%d] %s\033[0m\n' "$STEP" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

get_env() { grep -E "^$1=" "$ENVF" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
set_env() {  # set_env KEY VALUE  (never echoes the value)
  local tmp; tmp="$(mktemp)"
  grep -vE "^$1=" "$ENVF" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  cat "$tmp" > "$ENVF"; rm -f "$tmp"
}

[[ "$(uname -s)" == "Darwin" ]] || die "Run this on your Mac."
[[ $EUID -ne 0 ]] || die "Run as yourself, not root (it asks for sudo when needed)."
[[ -x /usr/local/bin/bastion ]] || die "Phase 1 isn't installed. Run ./scripts/bootstrap.sh first."
sudo -v

step "Container runtime"
if ! command -v docker >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || die "Homebrew is needed to install OrbStack."
  note "installing OrbStack"
  brew install --cask orbstack
fi
if ! docker info >/dev/null 2>&1; then
  open -a OrbStack 2>/dev/null || true
  note "waiting for Docker to start (finish OrbStack's first-run screen if it appears)..."
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 3; done
  docker info >/dev/null 2>&1 || die "Docker isn't running. Open OrbStack, then re-run this script."
fi
note "docker is running"

step "Update bastiond and turn on its edge API"
if [[ $UPDATE -eq 1 ]]; then
  "$REPO/scripts/bootstrap.sh" --update | tail -12 | sed 's/^/    /'
fi
sudo /usr/local/bin/bastion enable-edge-api --token-file "$REPO/deploy/.edge-token" \
  --quiet-bastiond-pushes | sed 's/^/    /'
sudo launchctl kickstart -k system/com.bastion.bastiond
note "indexing older events so agents can look up history (a minute or two the first time)"
sudo /usr/local/bin/bastion backfill-index | tail -1 | sed 's/^/    /'

step "Write deploy/.env"
if [[ ! -f "$ENVF" ]]; then
  cp "$REPO/deploy/.env.example" "$ENVF"
fi
chmod 600 "$ENVF"
set_env BASTION_EDGE_TOKEN "$(cat "$REPO/deploy/.edge-token")"
rm -f "$REPO/deploy/.edge-token"
if [[ -z "$(get_env BASTION_NTFY_TOPIC)" ]]; then
  set_env BASTION_NTFY_TOPIC "bastion-$(openssl rand -hex 12)"
fi
TS=""
for c in tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale; do
  if command -v "$c" >/dev/null 2>&1; then TS="$c"; break; fi
done
TSNAME=""
if [[ -n "$TS" ]]; then
  TSNAME="$("$TS" status --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -1)"
fi
if [[ -n "$TSNAME" ]]; then
  set_env NTFY_BASE_URL "https://$TSNAME:8443"
  set_env BASTION_CONSOLE_URL "https://$TSNAME"
  note "tailnet name: $TSNAME"
else
  warn "Tailscale name not found; pushes will only work on this Mac until it is set."
  [[ -n "$(get_env NTFY_BASE_URL)" ]] || set_env NTFY_BASE_URL "http://localhost:8090"
fi
if [[ -z "$(get_env ANTHROPIC_API_KEY)" ]]; then
  note "Create an API key at https://console.anthropic.com (set a \$25/month spend limit"
  note "on its workspace). It is stored only in deploy/.env (mode 600) and isn't displayed."
  if [[ -t 0 ]]; then
    read -r -s -p "    Paste your Anthropic API key (or press Return to add it later): " KEY; echo
    if [[ -n "$KEY" ]]; then set_env ANTHROPIC_API_KEY "$KEY"; fi
    unset KEY
  fi
fi
[[ -n "$(get_env ANTHROPIC_API_KEY)" ]] || warn "No API key yet: agents will wait. Add it to deploy/.env and re-run."

step "Build and start the containers (the first build takes a few minutes)"
"${COMPOSE[@]}" up -d --build 2>&1 | tail -6 | sed 's/^/    /'

step "Share the incident page and ntfy with your tailnet"
if [[ -n "$TS" && -n "$TSNAME" ]]; then
  if "$TS" serve --bg --https=443 http://127.0.0.1:8787 >/dev/null 2>&1 \
     && "$TS" serve --bg --https=8443 http://127.0.0.1:8090 >/dev/null 2>&1; then
    note "incident page: https://$TSNAME"
    note "ntfy server:   https://$TSNAME:8443"
  else
    warn "tailscale serve failed. In the Tailscale admin console, turn on MagicDNS and"
    warn "HTTPS certificates (DNS page), then re-run this script."
  fi
else
  warn "Skipped: Tailscale CLI not found."
fi

step "Checks"
sleep 5
"${COMPOSE[@]}" exec -T core bastion-core check --push | sed 's/^/    /' || true

cat <<EOF2

Done. What's running:
  Incident page   http://localhost:8787${TSNAME:+   (phone: https://$TSNAME)}
  Phoenix traces  http://localhost:6006
  ntfy            http://localhost:8090${TSNAME:+   (phone: https://$TSNAME:8443)}

On your iPhone, in the ntfy app: + > turn on "Use another server" >
  server ${TSNAME:+https://$TSNAME:8443}   topic $(get_env BASTION_NTFY_TOPIC)
(You can remove the old ntfy.sh subscription.)

Next: fire the test detections and grade the agents against the labeled set:
  ./scripts/test-triggers.sh
  docker compose -f deploy/docker-compose.yml exec core bastion-core eval
EOF2
