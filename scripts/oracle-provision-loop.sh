#!/usr/bin/env bash
# Repeats scripts/oracle-provision.sh while Oracle reports no capacity, so one workflow
# run keeps trying for hours. GitHub's schedule drops many runs; this way a dropped
# trigger costs nothing as long as another one starts the next long run.
#
# Env: RETRY_EVERY (seconds, default 600), RETRY_FOR (seconds, default 18000 = 5 h),
# plus everything oracle-provision.sh needs. Writes the last attempt's result and detail
# to $GITHUB_OUTPUT. Stops early on any result other than "capacity".
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
EVERY="${RETRY_EVERY:-600}"
FOR="${RETRY_FOR:-18000}"
OUT="${GITHUB_OUTPUT:-/dev/stdout}"
TRY="$(mktemp)"
trap 'rm -f "$TRY"' EXIT
deadline=$((SECONDS + FOR))
attempt=0

while true; do
  attempt=$((attempt + 1))
  : > "$TRY"
  echo "--- attempt $attempt ($(date -u +%H:%MZ))"
  GITHUB_OUTPUT="$TRY" "$HERE/oracle-provision.sh"
  result="$(sed -n 's/^result=//p' "$TRY")"
  if [[ "$result" != capacity || $((SECONDS + EVERY)) -ge $deadline ]]; then
    cat "$TRY" >> "$OUT"
    echo "attempts=$attempt" >> "$OUT"
    exit 0
  fi
  sleep "$EVERY"
done
