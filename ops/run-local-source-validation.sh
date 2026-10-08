#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
mode="${1:-quick}"
[[ "$mode" == quick || "$mode" == full ]] || { echo 'Usage: run-local-source-validation.sh [quick|full]' >&2; exit 2; }

set -a
# shellcheck disable=SC1091
source ./.env
set +a

api=http://127.0.0.1:8080/api
work_dir="$(mktemp -d data/tmp/source-validation.XXXXXX)"
auth_file="$work_dir/curl.conf"
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"
printf 'silent\nshow-error\nfail\nheader = "X-Control-Plane-Token: %s"\n' "$CONTROL_PLANE_TOKEN" >"$auth_file"
chmod 600 "$auth_file"
api_get() { curl --config "$auth_file" "$api$1"; }
api_post() { curl --config "$auth_file" -H 'Content-Type: application/json' -X POST "$api$1" -d "$2"; }

fixture="$work_dir/fixture"
mkdir -p "$fixture"
cat >"$fixture/app.py" <<'PY'
import subprocess

def run_command(user_input):
    return subprocess.call(user_input, shell=True)
PY
cat >"$fixture/app.js" <<'JS'
function unsafeRender(input) { return eval(input); }
module.exports = unsafeRender;
JS
cat >"$fixture/check.sh" <<'SH'
#!/bin/sh
target=$1
rm -rf $target
SH
cat >"$fixture/Dockerfile" <<'DOCKER'
FROM python:latest
WORKDIR /app
COPY . .
RUN chmod -R 777 /app
USER root
DOCKER
cat >"$fixture/main.tf" <<'TF'
resource "aws_security_group" "fixture" {
  ingress { from_port = 22; to_port = 22; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
}
TF
cat >"$fixture/pod.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: validation-fixture}
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext: {privileged: true}
YAML
cat >"$fixture/package.json" <<'JSON'
{"name":"local-validation-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}
JSON
printf '%s\n' 'fixture_aws_access_key = "AKIAIOSFODNN7EXAMPLE"' >"$fixture/example.txt"
chmod 700 "$fixture/check.sh"
(cd "$fixture" && python3 -m zipfile -c ../source-validation.zip .)

project_id="$(api_get /projects | jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' | head -n1)"
[[ -n "$project_id" ]]
artifact_id="$(curl --config "$auth_file" -X POST "$api/projects/$project_id/source-artifacts" \
  -F "archive=@$work_dir/source-validation.zip;type=application/zip" \
  -F 'requested_by=local-source-validation' \
  -F 'authorization_reference=locally-generated-validation-fixture' \
  -F 'authorization_confirmed=true' | jq -r .id)"
echo "Uploaded authorized local source fixture: $artifact_id"

tools=(semgrep bandit shellcheck hadolint njsscan checkov)
if [[ "$mode" == full ]]; then
  tools+=(gitleaks trufflehog trivy osv-scanner syft grype kics kubescape)
fi

total_observations=0
for tool_id in "${tools[@]}"; do
  payload="$(jq -nc --arg source "$artifact_id" --arg tool "$tool_id" '{source_artifact_id:$source,tool_id:$tool,profile:"source-assisted",requested_by:"local-source-validation",approval_confirmed:true}')"
  run_id="$(api_post "/projects/$project_id/runs" "$payload" | jq -r .id)"
  echo "Queued $tool_id: $run_id"
  status=queued
  for _ in $(seq 1 360); do
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
  total_observations=$((total_observations + observations))
  integrity="$(api_get "/projects/$project_id/evidence-integrity" | jq -r --arg run "$run_id" '.runs[] | select(.run_id == $run) | .integrity_status')"
  echo "$tool_id succeeded: observations=$observations integrity=$integrity"
  [[ "$integrity" == verified ]]
done

echo "Source validation observations: $total_observations"
[[ "$total_observations" -ge 1 ]]
echo "LOCAL SOURCE VALIDATION PASSED ($mode)"
