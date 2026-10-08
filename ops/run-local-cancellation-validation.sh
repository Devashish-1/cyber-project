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

payload="$(jq -nc --arg target "$target_id" '{target_id:$target,tool_id:"zap-passive",profile:"observe",requested_by:"local-cancellation-validation",approval_confirmed:true}')"
run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
echo "Queued cancellable local run: $run_id"

for _ in $(seq 1 30); do
  status="$(api_get "/runs/$run_id" | jq -r .status)"
  echo "Pre-cancel status: $status"
  [[ "$status" == running ]] && break
  [[ "$status" =~ ^(succeeded|failed|cancelled)$ ]] && exit 1
  sleep 1
done
[[ "$status" == running ]]

cancel_status="$(api_post "/runs/$run_id/cancel" '' | jq -r .status)"
echo "Cancellation accepted: $cancel_status"
[[ "$cancel_status" == cancelling ]]

for _ in $(seq 1 60); do
  status="$(api_get "/runs/$run_id" | jq -r .status)"
  echo "Post-cancel status: $status"
  [[ "$status" =~ ^(cancelled|succeeded|failed)$ ]] && break
  sleep 1
done
[[ "$status" == cancelled ]]

if docker ps -a --format '{{.Names}}' | grep -Fxq "security-run-$run_id"; then
  echo 'Cancelled tool container still exists' >&2
  exit 1
fi

integrity_json="$(api_get "/projects/$project_id/evidence-integrity")"
integrity_status="$(jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status' <<<"$integrity_json")"
echo "Final status: $status; evidence integrity: $integrity_status"
[[ "$integrity_status" == verified ]]
find "evidence/runs/$run_id" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
echo 'LOCAL CANCELLATION VALIDATION PASSED'
