#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
tool_filter="${1:-naabu,nmap,katana}"
set -a
# shellcheck disable=SC1091
. ./.env
set +a

api=http://127.0.0.1:8080/api
work_dir="$(mktemp -d data/tmp/target-validation.XXXXXX)"
auth_file="$work_dir/curl.conf"
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"
printf 'silent\nshow-error\nfail\nheader = "X-Control-Plane-Token: %s"\n' "$CONTROL_PLANE_TOKEN" >"$auth_file"
chmod 600 "$auth_file"
api_get() { curl --config "$auth_file" "$api$1"; }
api_post() { curl --config "$auth_file" -H 'Content-Type: application/json' -X POST "$api$1" -d "$2"; }

lab_ip="$(docker inspect security-platform-local-lab --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$lab_ip" =~ ^172\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
target_url="http://$lab_ip/?id=1"
project_id="$(api_get /projects | jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' | head -n1)"
[[ -n "$project_id" ]]

target_id="$(api_get "/projects/$project_id/targets" | jq -r --arg url "$target_url" '.targets[] | select(.base_url == $url) | .id' | head -n1)"
if [[ -z "$target_id" ]]; then
  target_payload="$(jq -nc --arg url "$target_url" --arg host "$lab_ip" '{base_url:$url,allowed_hosts:[$host],excluded_paths:["/logout"],max_run_seconds:900,allow_state_changing:true,allow_third_party_services:false,authorization_reference:"locally-owned-docker-validation-lab",authorization_confirmed:true}')"
  target_id="$(api_post "/projects/$project_id/targets" "$target_payload" | jq -r .id)"
fi

IFS=',' read -r -a tools <<<"$tool_filter"
allowed=' arjun dalfox feroxbuster ffuf gobuster katana kiterunner naabu nikto nmap nuclei-reviewed sqlmap-controlled wapiti zap-baseline zap-full '
for tool_id in "${tools[@]}"; do
  [[ "$allowed" == *" $tool_id "* ]] || { echo "Tool is not approved for this local fixture: $tool_id" >&2; exit 2; }
done

adapter_json="$(api_get /adapters)"
completed=0
for tool_id in "${tools[@]}"; do
  profile="$(jq -r --arg tool "$tool_id" '.adapters[$tool].profile // empty' <<<"$adapter_json")"
  [[ -n "$profile" ]]
  payload="$(jq -nc --arg target "$target_id" --arg tool "$tool_id" --arg profile "$profile" '{target_id:$target,tool_id:$tool,profile:$profile,requested_by:"local-target-validation",approval_confirmed:true}')"
  run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
  echo "Queued $tool_id: $run_id ($target_url)"
  status=queued
  for _ in $(seq 1 480); do
    status="$(api_get "/runs/$run_id" | jq -r .status)"
    [[ "$status" =~ ^(succeeded|failed|cancelled)$ ]] && break
    sleep 2
  done
  run_json="$(api_get "/runs/$run_id")"
  if [[ "$status" != succeeded ]]; then
    jq '{id,tool_id,status,error_message}' <<<"$run_json" >&2
    exit 1
  fi
  observations="$(api_get "/runs/$run_id/observations" | jq '.observations | length')"
  integrity="$(api_get "/projects/$project_id/evidence-integrity" | jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status')"
  echo "$tool_id succeeded: observations=$observations integrity=$integrity"
  [[ "$integrity" == verified ]]
  completed=$((completed + 1))
done

[[ "$completed" -eq "${#tools[@]}" ]]
echo "LOCAL TARGET ADAPTER VALIDATION PASSED ($completed tools)"
