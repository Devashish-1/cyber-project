#!/usr/bin/env bash
set -euo pipefail

platform_root="${SECURITY_PLATFORM_ROOT:-/home/killswitch/security-platform}"
base_url="${SECURITY_PLATFORM_URL:-http://127.0.0.1:8080/api}"
cd "$platform_root"

./ops/test-adapter-contracts.sh >/dev/null

set -a
. ./.env
set +a

umask 077
work_dir="$(mktemp -d /tmp/security-platform-smoke.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT
curl_config="$work_dir/curl.conf"
printf 'silent\nshow-error\nfail\nheader = "x-control-plane-token: %s"\n' \
  "$CONTROL_PLANE_TOKEN" > "$curl_config"

curl -fsS "$base_url/health" | jq -e '
  .status == "ok" and .database == "ok" and .queue == "ok"
' >/dev/null
curl -fsS "${base_url%/api}/" > "$work_dir/dashboard.html"
grep -q 'UI v0.129' "$work_dir/dashboard.html"
grep -q 'authenticated_role' "$work_dir/dashboard.html"
grep -q 'Download DefectDojo JSON' "$work_dir/dashboard.html"
grep -q 'Download Faraday SARIF' "$work_dir/dashboard.html"
grep -q 'Read-only viewer mode' "$work_dir/dashboard.html"
grep -q "const mutatingActions=new Set" "$work_dir/dashboard.html"
grep -q 'new MutationObserver' "$work_dir/dashboard.html"
grep -q 'id="tool-status"' "$work_dir/dashboard.html"
grep -q 'runtime is not ready' "$work_dir/dashboard.html"
grep -q 'Download audit JSON' "$work_dir/dashboard.html"
grep -q 'Project adapter coverage' "$work_dir/dashboard.html"

unauthenticated_status="$(curl -sS -o /dev/null -w '%{http_code}' "$base_url/projects")"
test "$unauthenticated_status" = "401"

curl --config "$curl_config" "$base_url/session" | jq -e '
  .role == "operator" and .read_only == false and (.permissions | index("operate") != null)
' >/dev/null
if [ -n "${CONTROL_PLANE_VIEWER_TOKEN:-}" ]; then
  viewer_config="$work_dir/viewer-curl.conf"
  printf 'silent\nshow-error\nfail\nheader = "x-control-plane-token: %s"\n' \
    "$CONTROL_PLANE_VIEWER_TOKEN" > "$viewer_config"
  curl --config "$viewer_config" "$base_url/session" | jq -e '
    .role == "viewer" and .read_only == true and .permissions == ["read"]
  ' >/dev/null
  curl --config "$viewer_config" "$base_url/projects" | jq -e '.projects | type == "array"' >/dev/null
  viewer_write_status="$(curl --config "$viewer_config" --no-fail -sS -o "$work_dir/viewer-write.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' -X POST "$base_url/projects" \
    -d '{"name":"Viewer must not create","description":"RBAC smoke test"}')"
  test "$viewer_write_status" = "403"
  jq -e '.detail == "Viewer role is read-only"' "$work_dir/viewer-write.json" >/dev/null
fi

curl --config "$curl_config" "$base_url/openapi.json" > "$work_dir/openapi.json"
jq -e '
  (.info.version | type == "string") and
  (.paths["/local-validation-status"] != null) and
  (.paths["/local-source-validation-status"] != null) and
  (.paths["/image-audit-status"] != null) and
  (.paths["/image-audit-history"] != null) and
  (.paths["/backup-status"] != null) and
  (.paths["/deployment-security-status"] != null) and
  (.paths["/image-audit-artifacts/{artifact_kind}"] != null) and
  (.paths["/projects/{project_id}/report.json"] != null) and
  (.paths["/projects/{project_id}/report.sarif"] != null) and
  (.paths["/projects/{project_id}/report.defectdojo.json"] != null) and
  (.paths["/projects/{project_id}/report.md"] != null) and
  (.paths["/projects/{project_id}/report-bundle.zip"] != null)
  and (.paths["/projects/{project_id}/audit-events.json"] != null)
  and (.paths["/projects/{project_id}/adapter-coverage"] != null)
' "$work_dir/openapi.json" >/dev/null

curl --config "$curl_config" "$base_url/deployment-security-status" > "$work_dir/deployment-security.json"
jq -e '
  (.available == true) and
  (.enforced == true) and
  (.fresh == true) and
  (.age_seconds <= 600) and
  ((.services | length) == 3) and
  all(.services[]; .read_only and .capabilities_dropped and .no_new_privileges and .non_root and .running)
' "$work_dir/deployment-security.json" >/dev/null

curl --config "$curl_config" "$base_url/projects" > "$work_dir/projects.json"
jq -e '.projects | type == "array"' "$work_dir/projects.json" >/dev/null
curl --config "$curl_config" "$base_url/coverage" > "$work_dir/coverage.json"
jq -e '
  .totals.implemented > 0 and
  (.totals.immutable_images == .totals.implemented) and
  (.totals.floating_images == 0) and
  (.totals.validated > 0) and
  (.totals.validation_pending >= 0) and
  ((.validation | length) == .totals.implemented) and
  (([.validation[] | select(.validated == true)] | length) == .totals.validated) and
  ([.validation[] | has("current_image") and has("proven_image") and has("image_matches") and has("integrity_status") and has("validation_state") and has("validation_note") and has("requires_external_approval")] | all) and
  ([.validation[] | select(.requires_external_approval == true) | (.validation_state == "proven" or .validation_state == "external-approval-required")] | all) and
  ([.validation[] | select(.validated == true) | (.image_matches == true and .integrity_status == "verified")] | all)
' "$work_dir/coverage.json" >/dev/null
jq -e '
  ([.non_adapter[] | select(.id == "defectdojo")][0].export_format == "generic-findings-json") and
  ([.non_adapter[] | select(.id == "faraday")][0].export_format == "sarif-2.1.0")
' "$work_dir/coverage.json" >/dev/null
curl --config "$curl_config" "$base_url/local-validation-status" > "$work_dir/local-validation.json"
jq -e '
  (.available == true) and
  (.status == "running" or .status == "passed" or .status == "failed") and
  (.mode == "quick" or .mode == "full" or .mode == "exhaustive") and
  (.age_seconds | type == "number")
' "$work_dir/local-validation.json" >/dev/null
curl --config "$curl_config" "$base_url/local-source-validation-status" > "$work_dir/local-source-validation.json"
jq -e '
  (.available == true) and
  (.status == "running" or .status == "passed" or .status == "failed") and
  (.mode == "quick" or .mode == "full") and
  (.completed_tools | type == "number") and
  (.total_observations | type == "number") and
  (.age_seconds | type == "number")
' "$work_dir/local-source-validation.json" >/dev/null
curl --config "$curl_config" "$base_url/image-audit-status" > "$work_dir/image-audit.json"
jq -e '
  (.available == true) and
  (.fresh | type == "boolean") and
  (.age_seconds | type == "number") and
  (.severity_counts.critical | type == "number") and
  (.fixable_counts.high | type == "number") and
  (.sbom.available == true) and
  (.checksums.available == true) and
  (.checksums.verified == true)
' "$work_dir/image-audit.json" >/dev/null
curl --config "$curl_config" "$base_url/image-audit-history?limit=10" > "$work_dir/image-audit-history.json"
jq -e '(.audits | type == "array") and (.audits | length >= 1) and (.audits[0].integrity_verified == true)' "$work_dir/image-audit-history.json" >/dev/null
curl --config "$curl_config" "$base_url/backup-status" > "$work_dir/backup-status.json"
jq -e '(.available == true) and (.paired == true) and (.verified == true) and (.fresh | type == "boolean") and (.restore_validation.status == "passed") and (.restore_validation.matches_latest == true)' "$work_dir/backup-status.json" >/dev/null
mkdir "$work_dir/image-audit"
for kind in report sbom checksums; do
  filename="$(jq -r --arg kind "$kind" 'if $kind == "report" then .report.filename elif $kind == "sbom" then .sbom.filename else .checksums.filename end' "$work_dir/image-audit.json")"
  curl --config "$curl_config" "$base_url/image-audit-artifacts/$kind" > "$work_dir/image-audit/$filename"
  test -s "$work_dir/image-audit/$filename"
done
(cd "$work_dir/image-audit" && sha256sum -c "$(jq -r '.checksums.filename' ../image-audit.json)" >/dev/null)
project_id="$(jq -r '.projects[0].id // empty' "$work_dir/projects.json")"

local_project_id="$(jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' "$work_dir/projects.json" | head -n1)"
if [ -n "$local_project_id" ]; then
  curl --config "$curl_config" "$base_url/projects/$local_project_id/targets" > "$work_dir/local-targets.json"
  local_target_id="$(jq -r '.targets[] | select(.allow_third_party_services == false) | .id' "$work_dir/local-targets.json" | head -n1)"
  if [ -n "$local_target_id" ]; then
    third_party_status="$(curl --config "$curl_config" --no-fail -sS -o "$work_dir/third-party-denied.json" -w '%{http_code}' \
      -H 'Content-Type: application/json' -X POST "$base_url/projects/$local_project_id/runs" \
      -d "{\"target_id\":\"$local_target_id\",\"tool_id\":\"subfinder\",\"profile\":\"controlled-active\",\"requested_by\":\"smoke-policy-check\",\"approval_confirmed\":true}")"
    test "$third_party_status" = 409
    jq -e '.detail | contains("third-party")' "$work_dir/third-party-denied.json" >/dev/null
  fi
fi

if [ -n "$project_id" ]; then
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.json?include_info=true" \
    > "$work_dir/report.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/findings" \
    > "$work_dir/findings.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/adapter-coverage" \
    > "$work_dir/adapter-coverage.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.sarif?include_info=true" \
    > "$work_dir/report.sarif"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.defectdojo.json?include_info=true" \
    > "$work_dir/report.defectdojo.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.md?include_info=true" \
    > "$work_dir/report.md"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/audit-events.json" \
    > "$work_dir/audit-events.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report-bundle.zip?include_info=true" \
    > "$work_dir/report-bundle.zip"
  jq -e --arg project_id "$project_id" '
    .schema == "security-platform-report/v1" and
    .project.id == $project_id and
    (.summary.unique_findings == (.findings | length)) and
    all(.findings[]; (.credential_role == null or (.credential_role | type) == "string")) and
    (.coverage.adapter_gaps.unattempted_adapters | type == "array") and
    (.coverage.adapter_gaps.attempted_coverage_percent | type == "number")
  ' "$work_dir/report.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.available_adapters | type == "array") and
    (.attempted_adapters | type == "array") and
    (.successful_adapters | type == "array") and
    (.unattempted_adapters | type == "array")
  ' "$work_dir/adapter-coverage.json" >/dev/null
  jq -e '
    .version == "2.1.0" and
    (.runs | type == "array") and
    all(.runs[].results[]?;
      (.properties.authenticatedRole == null or (.properties.authenticatedRole | type) == "string")
    )
  ' \
    "$work_dir/report.sarif" >/dev/null
  jq -e '
    .type == "Security Testing Platform" and
    (.version | type == "string") and
    (.findings | type == "array") and
    all(.findings[];
      (.title | type == "string") and
      (.description | type == "string") and
      (.severity == "Critical" or .severity == "High" or .severity == "Medium" or .severity == "Low" or .severity == "Info") and
      (.active | type == "boolean") and
      (.verified | type == "boolean") and
      (.false_p | type == "boolean") and
      (.risk_accepted | type == "boolean") and
      (.is_mitigated | type == "boolean") and
      (.unique_id_from_tool | type == "string")
    )
  ' "$work_dir/report.defectdojo.json" >/dev/null
  grep -q '^# Security assessment report' "$work_dir/report.md"
  jq -e --arg project_id "$project_id" '
    .schema == "security-platform-audit/v1" and
    .project_id == $project_id and
    (.event_count == (.events | length)) and
    (.truncated | type == "boolean")
  ' "$work_dir/audit-events.json" >/dev/null
  test "$(jq -r '.summary.unique_findings' "$work_dir/report.json")" = \
    "$(jq -r '.unique_count' "$work_dir/findings.json")"
  jq -e 'all(.findings[]; (.credential_role == null or (.credential_role | type) == "string"))' \
    "$work_dir/findings.json" >/dev/null
  mkdir "$work_dir/bundle"
  unzip -q "$work_dir/report-bundle.zip" -d "$work_dir/bundle"
  test "$(find "$work_dir/bundle" -maxdepth 1 -type f | wc -l)" = "6"
  jq -e '.schema == "security-platform-audit/v1"' "$work_dir/bundle/audit-events.json" >/dev/null
  (cd "$work_dir/bundle" && sha256sum -c manifest.sha256 >/dev/null)
fi

sha256sum -c config/manifest.sha256 >/dev/null
docker compose ps --format json > "$work_dir/compose.jsonl"
jq -s -e '
  length >= 5 and
  all(.[]; .State == "running") and
  all(.[]; (.Health == "" or .Health == "healthy"))
' "$work_dir/compose.jsonl" >/dev/null

printf 'Smoke test passed: API %s, %s project(s), all services operational\n' \
  "$(jq -r '.info.version' "$work_dir/openapi.json")" \
  "$(jq -r '.projects | length' "$work_dir/projects.json")"
