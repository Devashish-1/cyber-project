#!/usr/bin/env bash
set -euo pipefail

platform_root="${SECURITY_PLATFORM_ROOT:-/home/killswitch/security-platform}"
base_url="${SECURITY_PLATFORM_URL:-http://127.0.0.1:8080/api}"
cd "$platform_root"

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

unauthenticated_status="$(curl -sS -o /dev/null -w '%{http_code}' "$base_url/projects")"
test "$unauthenticated_status" = "401"

curl --config "$curl_config" "$base_url/openapi.json" > "$work_dir/openapi.json"
jq -e '
  (.info.version | type == "string") and
  (.paths["/image-audit-status"] != null) and
  (.paths["/image-audit-artifacts/{artifact_kind}"] != null) and
  (.paths["/projects/{project_id}/report.json"] != null) and
  (.paths["/projects/{project_id}/report.sarif"] != null) and
  (.paths["/projects/{project_id}/report.md"] != null) and
  (.paths["/projects/{project_id}/report-bundle.zip"] != null)
' "$work_dir/openapi.json" >/dev/null

curl --config "$curl_config" "$base_url/projects" > "$work_dir/projects.json"
jq -e '.projects | type == "array"' "$work_dir/projects.json" >/dev/null
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
mkdir "$work_dir/image-audit"
for kind in report sbom checksums; do
  filename="$(jq -r --arg kind "$kind" 'if $kind == "report" then .report.filename elif $kind == "sbom" then .sbom.filename else .checksums.filename end' "$work_dir/image-audit.json")"
  curl --config "$curl_config" "$base_url/image-audit-artifacts/$kind" > "$work_dir/image-audit/$filename"
  test -s "$work_dir/image-audit/$filename"
done
(cd "$work_dir/image-audit" && sha256sum -c "$(jq -r '.checksums.filename' ../image-audit.json)" >/dev/null)
project_id="$(jq -r '.projects[0].id // empty' "$work_dir/projects.json")"

if [ -n "$project_id" ]; then
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.json?include_info=true" \
    > "$work_dir/report.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/findings" \
    > "$work_dir/findings.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.sarif?include_info=true" \
    > "$work_dir/report.sarif"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report.md?include_info=true" \
    > "$work_dir/report.md"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/report-bundle.zip?include_info=true" \
    > "$work_dir/report-bundle.zip"
  jq -e --arg project_id "$project_id" '
    .schema == "security-platform-report/v1" and
    .project.id == $project_id and
    (.summary.unique_findings == (.findings | length))
  ' "$work_dir/report.json" >/dev/null
  jq -e '.version == "2.1.0" and (.runs | type == "array")' \
    "$work_dir/report.sarif" >/dev/null
  grep -q '^# Security assessment report' "$work_dir/report.md"
  test "$(jq -r '.summary.unique_findings' "$work_dir/report.json")" = \
    "$(jq -r '.unique_count' "$work_dir/findings.json")"
  mkdir "$work_dir/bundle"
  unzip -q "$work_dir/report-bundle.zip" -d "$work_dir/bundle"
  test "$(find "$work_dir/bundle" -maxdepth 1 -type f | wc -l)" = "4"
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
