#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
set -a
# shellcheck disable=SC1091
. ./.env
set +a

python_image='python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c'
dns_lab='security-platform-dns-lab'
api_lab='security-platform-openapi-lab'

docker rm -f "$dns_lab" "$api_lab" >/dev/null 2>&1 || true
docker run -d --name "$dns_lab" --restart unless-stopped \
  --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true --user 65534:65534 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
  -v "$PWD/backend/tests/fixtures/local_dns_lab.py:/lab.py:ro" \
  "$python_image" python /lab.py >/dev/null
docker run -d --name "$api_lab" --restart unless-stopped \
  -p 172.17.0.1:18081:8000 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 65534:65534 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
  -v "$PWD/backend/tests/fixtures/local_openapi_lab.py:/lab.py:ro" \
  "$python_image" python /lab.py >/dev/null

sleep 2
dns_ip="$(docker inspect "$dns_lab" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$dns_ip" =~ ^172\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
docker exec "$api_lab" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/openapi.json", timeout=2).read()'
docker compose exec -T runner python -c 'import urllib.request; urllib.request.urlopen("http://172.17.0.1:18081/openapi.json", timeout=2).read()'

api=http://127.0.0.1:8080/api
work_dir="$(mktemp -d data/tmp/remaining-validation.XXXXXX)"
auth_file="$work_dir/curl.conf"
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"
printf 'silent\nshow-error\nfail\nheader = "X-Control-Plane-Token: %s"\n' "$CONTROL_PLANE_TOKEN" >"$auth_file"
chmod 600 "$auth_file"
api_get() { curl --config "$auth_file" "$api$1"; }
api_post() { curl --config "$auth_file" -H 'Content-Type: application/json' -X POST "$api$1" -d "$2"; }

project_id="$(api_get /projects | jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' | head -n1)"
[[ -n "$project_id" ]]

create_or_get_target() {
  local url="$1" host="$2" resolver="${3:-}" payload
  local existing
  existing="$(api_get "/projects/$project_id/targets" | jq -r --arg url "$url" '.targets[] | select(.base_url == $url) | .id' | head -n1)"
  if [[ -n "$existing" ]]; then
    printf '%s' "$existing"
    return
  fi
  payload="$(jq -nc --arg url "$url" --arg host "$host" --arg resolver "$resolver" '{base_url:$url,allowed_hosts:[$host],excluded_paths:[],dns_resolver:(if $resolver=="" then null else $resolver end),max_run_seconds:180,allow_state_changing:false,allow_third_party_services:false,authorization_reference:"locally-owned-validation-fixture",authorization_confirmed:true}')"
  api_post "/projects/$project_id/targets" "$payload" | jq -r .id
}

dns_target="$(create_or_get_target 'http://lab.security-platform.test/' 'lab.security-platform.test' "$dns_ip:53")"
schema_target="$(create_or_get_target 'http://172.17.0.1:18081/openapi.json' '172.17.0.1')"
adapter_json="$(api_get /adapters)"

run_tool() {
  local tool_id="$1" target_id="$2" profile payload run_id status observations integrity
  profile="$(jq -r --arg tool "$tool_id" '.adapters[$tool].profile' <<<"$adapter_json")"
  payload="$(jq -nc --arg target "$target_id" --arg tool "$tool_id" --arg profile "$profile" '{target_id:$target,tool_id:$tool,profile:$profile,requested_by:"local-fixture-validation",approval_confirmed:true}')"
  run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
  echo "Queued $tool_id: $run_id"
  status=queued
  for _ in $(seq 1 180); do
    status="$(api_get "/runs/$run_id" | jq -r .status)"
    [[ "$status" =~ ^(succeeded|failed|cancelled)$ ]] && break
    sleep 2
  done
  if [[ "$status" != succeeded ]]; then
    api_get "/runs/$run_id" | jq '{id,tool_id,status,error_message}' >&2
    exit 1
  fi
  observations="$(api_get "/runs/$run_id/observations" | jq '.observations | length')"
  integrity="$(api_get "/projects/$project_id/evidence-integrity" | jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status')"
  echo "$tool_id succeeded: observations=$observations integrity=$integrity"
  [[ "$integrity" == verified ]]
}

for tool in dnsx massdns dnsrecon; do run_tool "$tool" "$dns_target"; done
run_tool schemathesis "$schema_target"
echo 'LOCAL REMAINING ADAPTER VALIDATION PASSED (4 tools)'
