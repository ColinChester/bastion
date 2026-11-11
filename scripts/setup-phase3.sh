#!/usr/bin/env bash
# Bastion Phase 3 setup: the executor (in bastiond) and the action gateway (a container).
#
# Safe to re-run. It:
#   1. updates bastiond
#   2. creates the gateway's command-signing key (kept in deploy/.env.gateway, never shown)
#   3. turns on bastiond's executor in SHADOW mode, trusting only that key
#   4. starts the gateway container and rebuilds the others
#   5. runs the checks and tells you how to register your passkey
#
# Nothing here lets Bastion change your Mac. Shadow mode only logs what it would have
# done. After 14 days, you switch real actions on yourself:  sudo bastion autonomy on
#
#   ./scripts/setup-phase3.sh              full setup
#   ./scripts/setup-phase3.sh --no-update  skip reinstalling bastiond
#   ./scripts/setup-phase3.sh --new-key    replace the signing key (old commands stop working)
set -euo pipefail

UPDATE=1; NEWKEY=0
for a in "$@"; do
  case "$a" in
    --no-update) UPDATE=0 ;;
    --new-key) NEWKEY=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENVF="$REPO/deploy/.env"
GWF="$REPO/deploy/.env.gateway"
KEYTMP="$REPO/deploy/.gateway-key"
COMPOSE=(docker compose -f "$REPO/deploy/docker-compose.yml")
BASTION=/usr/local/bin/bastion
STEP=0

step() { STEP=$((STEP + 1)); printf '\n\033[1m[%d] %s\033[0m\n' "$STEP" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

get_env() { grep -E "^$2=" "$1" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
set_env() {  # set_env FILE KEY VALUE  (never echoes the value)
  local tmp; tmp="$(mktemp)"
  grep -vE "^$2=" "$1" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$2" "$3" >> "$tmp"
  cat "$tmp" > "$1"; rm -f "$tmp"
}

[[ "$(uname -s)" == "Darwin" ]] || die "Run this on your Mac."
[[ $EUID -ne 0 ]] || die "Run as yourself, not root (it asks for sudo when needed)."
[[ -x "$BASTION" ]] || die "Phase 1 isn't installed. Run ./scripts/bootstrap.sh first."
[[ -f "$ENVF" ]] || die "Phase 2 isn't set up. Run ./scripts/setup-phase2.sh first."
[[ -n "$(get_env "$ENVF" BASTION_EDGE_TOKEN)" ]] || die "deploy/.env has no edge token. Run ./scripts/setup-phase2.sh first."
docker info >/dev/null 2>&1 || die "Docker isn't running. Open OrbStack, then re-run this script."
sudo -v

step "Update bastiond"
if [[ $UPDATE -eq 1 ]]; then
  "$REPO/scripts/bootstrap.sh" --update | tail -12 | sed 's/^/    /'
else
  note "skipped (--no-update)"
fi
"$BASTION" gateway-keygen --help >/dev/null 2>&1 \
  || die "The installed bastion is older than Phase 3. Re-run without --no-update."

step "Console address (passkeys are tied to it)"
CONSOLE="$(get_env "$ENVF" BASTION_CONSOLE_URL)"
if [[ "$CONSOLE" == https://* ]]; then
  RP="${CONSOLE#https://}"; RP="${RP%%/*}"; RP="${RP%%:*}"
  note "console: $CONSOLE"
else
  CONSOLE="http://localhost:8787"; RP="localhost"
  warn "No Tailscale HTTPS address in deploy/.env, so approvals will only work in a"
  warn "browser on this Mac (http://localhost:8787). Fix Tailscale Serve with"
  warn "./scripts/setup-phase2.sh and re-run this script to approve from your phone."
fi

step "Gateway signing key"
touch "$GWF"; chmod 600 "$GWF"
if [[ $NEWKEY -eq 1 || -z "$(get_env "$GWF" BASTION_GATEWAY_KEY)" ]]; then
  rm -f "$KEYTMP"
  PUB="$("$BASTION" gateway-keygen --out "$KEYTMP")"
  set_env "$GWF" BASTION_GATEWAY_KEY "$(cat "$KEYTMP")"
  rm -f "$KEYTMP"
  set_env "$GWF" BASTION_GATEWAY_PUBLIC "$PUB"
  note "new key created (private half stays in deploy/.env.gateway, mode 600)"
else
  PUB="$(get_env "$GWF" BASTION_GATEWAY_PUBLIC)"
  note "keeping the existing key"
fi
[[ -n "$PUB" ]] || die "deploy/.env.gateway has a key but no public half. Re-run with --new-key."
if [[ -z "$(get_env "$ENVF" BASTION_GATEWAY_TOKEN)" ]]; then
  set_env "$ENVF" BASTION_GATEWAY_TOKEN "$(openssl rand -hex 32)"
fi
set_env "$GWF" BASTION_GATEWAY_TOKEN "$(get_env "$ENVF" BASTION_GATEWAY_TOKEN)"
set_env "$GWF" BASTION_EDGE_TOKEN "$(get_env "$ENVF" BASTION_EDGE_TOKEN)"
set_env "$ENVF" COMPOSE_PROFILES actions

step "Turn on the executor in shadow mode"
sudo "$BASTION" enable-executor --public-key "$PUB" --rp-id "$RP" --origin "$CONSOLE" \
  | sed 's/^/    /'
sudo launchctl kickstart -k system/com.bastion.bastiond
sleep 3
sudo "$BASTION" autonomy status | sed 's/^/    /'

step "Build and start the containers"
"${COMPOSE[@]}" up -d --build 2>&1 | tail -8 | sed 's/^/    /'

step "Checks"
sleep 5
"${COMPOSE[@]}" exec -T core bastion-core check | sed 's/^/    /' || true
sudo "$BASTION" doctor | grep -E "executor|passkey|audit" | sed 's/^/    /' || true

cat <<EOF2

Done. Bastion is in SHADOW mode: it records what it would have done and changes nothing.

1. Register your passkey (once per device you want to approve from):
     sudo bastion passkey enroll
   then open  $CONSOLE/enroll  on your phone and type the code it prints.

2. For the next 14 days, look at  $CONSOLE/approvals  now and then (or run
   sudo bastion actions). Every "shadow" line is something Bastion would have done.
   If any of them would have been wrong, tell Claude before going live.

3. When the 14 days are clean, switch real containment on yourself:
     sudo bastion autonomy on
   and off again at any time:
     sudo bastion autonomy off

Try it safely now:  ./scripts/test-triggers.sh   (shadow entries appear, nothing changes)
EOF2
