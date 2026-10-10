#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
set -a
# shellcheck disable=SC1091
. ./.env
set +a

api=http://127.0.0.1:8080/api
work_dir="$(mktemp -d data/tmp/k6-validation.XXXXXX)"
auth_file="$work_dir/curl.conf"
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"
printf 'silent\nshow-error\nfail\nheader = "X-Control-Plane-Token: %s"\n' \
  "$CONTROL_PLANE_TOKEN" > "$auth_file"
chmod 600 "$auth_file"
api_get() { curl --config "$auth_file" "$api$1"; }
api_post() { curl --config "$auth_file" -H 'Content-Type: application/json' -X POST "$api$1" -d "$2"; }

lab_ip="$(docker inspect security-platform-local-lab --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$lab_ip" =~ ^172\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
target_url="http://$lab_ip/?load=bounded-smoke"
project_id="$(api_get /projects | jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' | head -n1)"
[[ -n "$project_id" ]]

target_id="$(api_get "/projects/$project_id/targets" | jq -r --arg url "$target_url" '.targets[] | select(.base_url == $url and .allow_load_testing == true) | .id' | head -n1)"
if [[ -z "$target_id" ]]; then
  target_payload="$(jq -nc --arg url "$target_url" --arg host "$lab_ip" '{base_url:$url,allowed_hosts:[$host],excluded_paths:["/logout"],max_run_seconds:30,allow_state_changing:false,allow_third_party_services:false,allow_load_testing:true,authorization_reference:"locally-owned-bounded-k6-lab",authorization_confirmed:true}')"
  target_id="$(api_post "/projects/$project_id/targets" "$target_payload" | jq -r .id)"
fi

payload="$(jq -nc --arg target "$target_id" '{target_id:$target,tool_id:"k6",profile:"load-resilience",requested_by:"local-k6-validation",approval_confirmed:true}')"
run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
echo "Queued bounded local-only k6 run: $run_id ($target_url)"

status=queued
for _ in $(seq 1 60); do
  status="$(api_get "/runs/$run_id" | jq -r .status)"
  echo "Status: $status"
  [[ "$status" =~ ^(succeeded|failed|cancelled)$ ]] && break
  sleep 2
done

run_json="$(api_get "/runs/$run_id")"
observations="$(api_get "/runs/$run_id/observations")"
integrity="$(api_get "/projects/$project_id/evidence-integrity" | jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status')"
jq '{id,status,tool_id,profile,error_message}' <<<"$run_json"
jq '{status,observations}' <<<"$observations"
echo "Evidence integrity: $integrity"

[[ "$status" == succeeded ]]
jq -e '.observations | length == 1 and .[0].type == "load-resilience-smoke" and .[0].details.virtual_users == 1 and .[0].details.iterations == 1 and .[0].details.requests == 1 and .[0].details.response_body_retained == false' <<<"$observations" >/dev/null
[[ "$integrity" == verified ]]
echo 'LOCAL K6 VALIDATION PASSED'
