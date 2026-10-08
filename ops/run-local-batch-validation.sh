#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
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
target_id="$(api_get "/projects/$project_id/targets" | jq -r '.targets[] | select(.base_url == "http://172.17.0.2/") | .id' | head -n1)"
[[ -n "$project_id" && -n "$target_id" ]]

tools='["httpx","whatweb","zap-passive"]'
payload="$(jq -nc --arg target "$target_id" --argjson tools "$tools" '{target_id:$target,tool_ids:$tools,requested_by:"local-batch-validation",approval_confirmed:true}')"
batch_id="$(api_post "/projects/$project_id/batches" "$payload" | jq -r .id)"
echo "Queued local observe workflow: $batch_id"

status=queued
for _ in $(seq 1 360); do
  batch_json="$(api_get "/batches/$batch_id")"
  status="$(jq -r .status <<<"$batch_json")"
  summary="$(jq -r '[.runs[] | (.tool_id + "=" + .status)] | join(", ")' <<<"$batch_json")"
  echo "Batch: $status | $summary"
  [[ "$status" =~ ^(succeeded|failed|cancelled|partial)$ ]] && break
  sleep 2
done

jq '{id,status,plan_id,runs:[.runs[]|{id,tool_id,status,error_message}]}' <<<"$batch_json"
[[ "$status" == succeeded ]]
[[ "$(jq '[.runs[] | select(.status != "succeeded")] | length' <<<"$batch_json")" -eq 0 ]]

integrity_json="$(api_get "/projects/$project_id/evidence-integrity")"
while IFS= read -r run_id; do
  integrity_status="$(jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status' <<<"$integrity_json")"
  observations="$(api_get "/runs/$run_id/observations" | jq '.observations | length')"
  echo "Run $run_id: integrity=$integrity_status observations=$observations"
  [[ "$integrity_status" == verified ]]
  [[ "$observations" -ge 1 ]]
done < <(jq -r '.runs[].id' <<<"$batch_json")

echo 'LOCAL BATCH VALIDATION PASSED'
