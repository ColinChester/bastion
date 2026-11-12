#!/usr/bin/env bash
# One attempt to create the Oracle Cloud VM from its Resource Manager stack.
# Run every 30 minutes by .github/workflows/oracle-provision.yml until it succeeds.
#
# Writes one line to $GITHUB_OUTPUT (or stdout):
#   result=provisioned   the VM exists (now, or already)        -> workflow stops itself
#   result=capacity      Oracle had no A1 capacity (or 429)     -> try again next run
#   result=config        a setup problem retrying can't fix     -> workflow stops itself
#   result=error         something unexpected                   -> run fails, keeps trying
# and a short reason as detail=... It always exits 0 so the workflow can decide.
#
# Needs: oci (configured), jq. Env: OCI_STACK_ID, OCI_COMPARTMENT_ID,
# optional OCI_INSTANCE_NAME (default bastion-vm), POLL_SECONDS, MAX_POLLS.
set -euo pipefail

OCI="${OCI:-oci}"
: "${OCI_STACK_ID:?set OCI_STACK_ID}" "${OCI_COMPARTMENT_ID:?set OCI_COMPARTMENT_ID}"
NAME="${OCI_INSTANCE_NAME:-bastion-vm}"
POLL="${POLL_SECONDS:-20}"
MAX_POLLS="${MAX_POLLS:-60}"
OUT="${GITHUB_OUTPUT:-/dev/stdout}"
ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

finish() {  # finish RESULT DETAIL
  local detail="${2//$'\n'/ }"
  detail="${detail:0:300}"
  { echo "result=$1"; echo "detail=$detail"; } >> "$OUT"
  echo "result: $1 - $detail"
  exit 0
}

classify() {  # classify TEXT -> capacity|config|error
  if grep -qiE 'out of (host )?capacity|TooManyRequests|"status": ?429' <<<"$1"; then
    echo capacity
  elif grep -qiE 'NotAuthorizedOrNotFound|NotAuthenticated|LimitExceeded|QuotaExceeded|InvalidParameter|Could not find config|ConfigFileNotFound|InvalidPrivateKey|fingerprint|supply either a region|InvalidConfig|Invalid region' <<<"$1"; then
    echo config
  else
    echo error
  fi
}

first_line() {  # the most useful line of an error text
  grep -iE -m1 'capacity|error|exceeded|authoriz|invalid|429' <<<"$1" || head -c 300 <<<"$1"
}

count_instances() {  # instances named $NAME that aren't terminated; fails if the API does
  local out
  out="$("$OCI" compute instance list --compartment-id "$OCI_COMPARTMENT_ID" \
          --display-name "$NAME" --all 2>"$ERR")" || return 1
  [[ -z "$out" ]] && { echo 0; return 0; }
  jq -r '[.data[]? | select(."lifecycle-state" as $s
          | ["PROVISIONING","STARTING","RUNNING","STOPPING","STOPPED"] | index($s))] | length' \
     <<<"$out"
}

vm_exists() {  # exit status: 0 yes, 1 no; finishes the run if the API call fails
  local n e
  if ! n="$(count_instances)"; then
    e="$(cat "$ERR")"
    finish "$(classify "$e")" "listing instances failed: $(first_line "$e")"
  fi
  [[ "$n" -gt 0 ]]
}

if vm_exists; then
  finish provisioned "$NAME already exists"
fi

if ! job_json="$("$OCI" resource-manager job create-apply-job --stack-id "$OCI_STACK_ID" \
        --execution-plan-strategy AUTO_APPROVED --display-name "auto-provision-$(date +%s)" \
        2>"$ERR")"; then
  e="$(cat "$ERR")"
  finish "$(classify "$e")" "could not start an apply job: $(first_line "$e")"
fi
job="$(jq -r '.data.id' <<<"$job_json")"
echo "apply job: $job"

for _ in $(seq 1 "$MAX_POLLS"); do
  sleep "$POLL"
  if ! state="$("$OCI" resource-manager job get --job-id "$job" \
                 --query 'data."lifecycle-state"' --raw-output 2>"$ERR")"; then
    continue  # a failed status check is retried on the next poll
  fi
  case "$state" in
    SUCCEEDED)
      if vm_exists; then
        finish provisioned "stack applied; $NAME is up"
      fi
      finish config "the stack applied but no instance is named $NAME (set OCI_INSTANCE_NAME)"
      ;;
    FAILED|CANCELED)
      why="$("$OCI" resource-manager job get --job-id "$job" \
              --query 'data."failure-details".message' --raw-output 2>/dev/null || true)"
      logs="$("$OCI" resource-manager job get-job-logs-content --job-id "$job" 2>/dev/null || true)"
      finish "$(classify "$why $logs")" "apply job $state: $(first_line "$why $logs")"
      ;;
  esac
done
finish error "apply job $job still running after $((POLL * MAX_POLLS)) s"
