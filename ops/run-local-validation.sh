#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
tool_id="${1:-whatweb}"
target_url="${2:-http://172.17.0.2/}"
set -a
# shellcheck disable=SC1091
source ./.env
set +a

api=http://127.0.0.1:8080/api
auth_file="$(mktemp)"
trap 'rm -f "$auth_file"' EXIT
chmod 600 "$auth_file"
printf 'header = "X-Control-Plane-Token: %s"\n' "$CONTROL_PLANE_TOKEN" >"$auth_file"

api_get() { curl -fsS --config "$auth_file" "$api$1"; }
api_post() { curl -fsS --config "$auth_file" -H 'Content-Type: application/json' -X POST "$api$1" -d "$2"; }

project_id="$(api_get /projects | jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' | head -n1)"
if [[ -z "$project_id" ]]; then
  echo 'Local Runner Validation project was not found' >&2
  exit 1
fi

target_id="$(api_get "/projects/$project_id/targets" | jq -r --arg url "$target_url" '.targets[] | select(.base_url == $url) | .id' | head -n1)"
if [[ -z "$target_id" ]]; then
  echo "Authorized local lab target was not found: $target_url" >&2
  exit 1
fi

adapter_json="$(api_get /adapters)"
profile="$(jq -r --arg tool "$tool_id" '.adapters[$tool].profile // empty' <<<"$adapter_json")"
if [[ -z "$profile" ]]; then
  echo "Adapter is unavailable: $tool_id" >&2
  exit 1
fi
if [[ "$profile" != observe ]]; then
  echo "Local validation only permits observe-profile adapters (got: $profile)" >&2
  exit 1
fi

payload="$(jq -nc --arg target "$target_id" --arg tool "$tool_id" --arg profile "$profile" '{target_id:$target,tool_id:$tool,profile:$profile,requested_by:"local-validation",approval_confirmed:true}')"
run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
echo "Queued local-only run: $run_id ($tool_id -> $target_url)"

status=queued
for _ in $(seq 1 90); do
  status="$(api_get "/runs/$run_id" | jq -r .status)"
  echo "Status: $status"
  [[ "$status" =~ ^(succeeded|failed|cancelled)$ ]] && break
  sleep 2
done

run_json="$(api_get "/runs/$run_id")"
obs_json="$(api_get "/runs/$run_id/observations")"
count="$(jq '.observations | length' <<<"$obs_json")"
echo "Final status: $status; normalized observations: $count"
jq '{id,status,tool_id,profile,error_message}' <<<"$run_json"
jq '{types:(.observations | map(.type) | unique), severities:(.observations | group_by(.severity) | map({severity:.[0].severity,count:length}))}' <<<"$obs_json"

evidence_dir="evidence/runs/$run_id"
find "$evidence_dir" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort

[[ "$status" == succeeded ]]
[[ "$count" -ge 1 ]]
test -s "$evidence_dir/metadata.json"
test -s "$evidence_dir/events.jsonl"
echo 'LOCAL VALIDATION PASSED'
