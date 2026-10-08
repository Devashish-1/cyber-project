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
curl_config="$work_dir/curl.conf"
printf 'silent\nshow-error\nfail\nheader = "x-control-plane-token: %s"\n' \
  "$CONTROL_PLANE_TOKEN" > "$curl_config"
smoke_source_project_id=""
smoke_source_artifact_id=""
smoke_target_project_id=""
smoke_target_id=""
smoke_archived_project_id=""
cleanup_smoke_test() {
  if [ -n "$smoke_source_project_id" ] && [ -n "$smoke_source_artifact_id" ]; then
    curl --config "$curl_config" --no-fail -sS -o /dev/null \
      -H 'Content-Type: application/json' -X DELETE \
      "$base_url/projects/$smoke_source_project_id/source-artifacts/$smoke_source_artifact_id" \
      -d '{"requested_by":"smoke-cleanup","confirmation":"DELETE SOURCE ARCHIVE"}' || true
  fi
  if [ -n "$smoke_target_project_id" ] && [ -n "$smoke_target_id" ]; then
    curl --config "$curl_config" --no-fail -sS -o /dev/null \
      -H 'Content-Type: application/json' -X DELETE \
      "$base_url/projects/$smoke_target_project_id/targets/$smoke_target_id" \
      -d '{"requested_by":"smoke-cleanup","confirmation":"DELETE AUTHORIZED TARGET"}' || true
  fi
  if [ -n "$smoke_archived_project_id" ]; then
    curl --config "$curl_config" --no-fail -sS -o /dev/null \
      -H 'Content-Type: application/json' -X POST \
      "$base_url/projects/$smoke_archived_project_id/restore" \
      -d '{"requested_by":"smoke-cleanup"}' || true
  fi
  rm -rf "$work_dir"
}
trap cleanup_smoke_test EXIT

curl -fsS "$base_url/health" | jq -e '
  .status == "ok" and .database == "ok" and .queue == "ok"
' >/dev/null
curl -fsS "${base_url%/api}/" > "$work_dir/dashboard.html"
grep -q 'UI v0.164' "$work_dir/dashboard.html"
grep -q 'Delete import' "$work_dir/dashboard.html"
grep -q 'DELETE MANUAL IMPORT' "$work_dir/dashboard.html"
grep -q "msg('burp-import-message','Deleting the selected manual import" "$work_dir/dashboard.html"
grep -q 'Manual import history' "$work_dir/dashboard.html"
grep -q 'loadBurpImports' "$work_dir/dashboard.html"
grep -q 'id="finding-provenance"' "$work_dir/dashboard.html"
grep -q "provenance==='all'||f.provenance===provenance" "$work_dir/dashboard.html"
grep -q 'Assessment provenance' "$work_dir/dashboard.html"
grep -q 'assessment-provenance' "$work_dir/dashboard.html"
grep -q 'authenticated_role' "$work_dir/dashboard.html"
grep -q 'roleCoverageMap' "$work_dir/dashboard.html"
grep -q 'Download DefectDojo JSON' "$work_dir/dashboard.html"
grep -q 'Download Faraday SARIF' "$work_dir/dashboard.html"
grep -q 'Read-only viewer mode' "$work_dir/dashboard.html"
grep -q "const mutatingActions=new Set" "$work_dir/dashboard.html"
grep -q 'new MutationObserver' "$work_dir/dashboard.html"
grep -q 'id="tool-status"' "$work_dir/dashboard.html"
grep -q 'value="approval-required">External approval required' "$work_dir/dashboard.html"
grep -q "label:'external approval required'" "$work_dir/dashboard.html"
grep -q 'requires target-level opt-in and explicit authorization' "$work_dir/dashboard.html"
grep -q 'blocked until the selected target explicitly opts in' "$work_dir/dashboard.html"
grep -q 'Selected target policy does not allow third-party provider access' "$work_dir/dashboard.html"
grep -q "adapterMap\[tool\].uses_third_party_services&&!targetMap\[target\]?.allow_third_party_services" "$work_dir/dashboard.html"
grep -q "externalTools.length&&!targetMap\[target\]?.allow_third_party_services" "$work_dir/dashboard.html"
grep -q 'function validationEvidenceAction' "$work_dir/dashboard.html"
grep -q "validationEvidenceAction(item)" "$work_dir/dashboard.html"
grep -q "validationEvidenceAction(toolCoverageMap\[name\],'Review proof')" "$work_dir/dashboard.html"
grep -q 'function adapterRunPreparationAction' "$work_dir/dashboard.html"
grep -q 'function prepareAdapterRun' "$work_dir/dashboard.html"
grep -q 'then explicitly approve before queueing' "$work_dir/dashboard.html"
grep -q "el('run-approved').checked=false;adapterChanged()" "$work_dir/dashboard.html"
grep -q 'Current pinned runtime is unavailable' "$work_dir/dashboard.html"
grep -q "toolRuntimeMap\[id\]?.state!=='ready'" "$work_dir/dashboard.html"
grep -q 'Wait for the supervised runner inventory before preparing this gap' "$work_dir/dashboard.html"
grep -q 'State-changing access:' "$work_dir/dashboard.html"
grep -q 'does not allow state-changing extended-active tests' "$work_dir/dashboard.html"
grep -q "adapterMap\[tool\].profile==='extended-active'&&!targetMap\[target\]?.allow_state_changing" "$work_dir/dashboard.html"
grep -q "extendedTools.length&&!targetMap\[target\]?.allow_state_changing" "$work_dir/dashboard.html"
grep -q 'by server UTC' "$work_dir/dashboard.html"
grep -q 'Selected target testing window is currently closed' "$work_dir/dashboard.html"
grep -q "targetMap\[target\]?.testing_window_open===false" "$work_dir/dashboard.html"
grep -q 'runtime is not ready' "$work_dir/dashboard.html"
grep -q 'Download audit JSON' "$work_dir/dashboard.html"
grep -q 'Project adapter coverage' "$work_dir/dashboard.html"
grep -q 'Per-target coverage' "$work_dir/dashboard.html"
grep -q 'Coverage gap rollup' "$work_dir/dashboard.html"
grep -q 'project-coverage-gap-details' "$work_dir/dashboard.html"
grep -q 'prepareCoverageGapRun' "$work_dir/dashboard.html"
grep -q "el('run-approved').checked=false" "$work_dir/dashboard.html"
grep -q 'Download coverage gaps' "$work_dir/dashboard.html"
grep -q 'downloadCoverageGaps' "$work_dir/dashboard.html"
grep -q 'Official project' "$work_dir/dashboard.html"
grep -q 'Import sanitized findings' "$work_dir/dashboard.html"
grep -q 'raw HTTP requests, responses, cookies, and credentials are discarded' "$work_dir/dashboard.html"
grep -q 'manualImport' "$work_dir/dashboard.html"
grep -q 'Manual retest required' "$work_dir/dashboard.html"
grep -q 'DELETE SOURCE ARCHIVE' "$work_dir/dashboard.html"
grep -q 'deleteSourceArtifact' "$work_dir/dashboard.html"
grep -q 'DELETE AUTHORIZED TARGET' "$work_dir/dashboard.html"
grep -q 'deleteTarget' "$work_dir/dashboard.html"
grep -q 'ARCHIVE PROJECT' "$work_dir/dashboard.html"
grep -q 'archiveProject' "$work_dir/dashboard.html"
grep -q 'restoreProject' "$work_dir/dashboard.html"

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
  and (.paths["/projects/{project_id}/imports/burp/{run_id}"].delete != null)
  and (.paths["/projects/{project_id}/audit-events.json"] != null)
  and (.paths["/projects/{project_id}/adapter-coverage"] != null)
  and (.paths["/projects/{project_id}/role-coverage"] != null)
  and (.paths["/projects/{project_id}/target-coverage"] != null)
  and (.paths["/projects/{project_id}/source-coverage"] != null)
  and (.paths["/projects/{project_id}/coverage-gaps"] != null)
  and (.paths["/projects/{project_id}/coverage-gaps.json"] != null)
  and (.paths["/projects/{project_id}/imports/burp"].get != null)
  and (.paths["/projects/{project_id}/imports/burp"].post != null)
  and (.paths["/projects/{project_id}/source-artifacts/{artifact_id}"].delete != null)
  and (.paths["/projects/{project_id}/targets/{target_id}"].delete != null)
  and (.paths["/projects/{project_id}/archive"].post != null)
  and (.paths["/projects/{project_id}/restore"].post != null)
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
jq -e '(.projects | type == "array") and all(.projects[]; .archived_at == null and .archived_by == null)' "$work_dir/projects.json" >/dev/null
curl --config "$curl_config" "$base_url/projects?include_archived=true" > "$work_dir/projects-all.json"
jq -e '
  (.projects | type == "array") and
  all(.projects[]; has("archived_at") and has("archived_by"))
' "$work_dir/projects-all.json" >/dev/null
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
  ([.validation[] | select(.validated == true) | (.image_matches == true and .integrity_status == "verified")] | all) and
  ([.validation[] | select(.id == "amass" or .id == "theharvester" or .id == "spiderfoot")] | length) == 3 and
  ([.validation[] | select(.id == "amass" or .id == "theharvester" or .id == "spiderfoot") | .requires_external_approval] | all) and
  ([.non_adapter[] | select(.id == "amass" or .id == "theharvester" or .id == "spiderfoot")] | length) == 0
' "$work_dir/coverage.json" >/dev/null
jq -e '
  ([.non_adapter[] | select(.id == "defectdojo")][0].export_format == "generic-findings-json") and
  ([.non_adapter[] | select(.id == "faraday")][0].export_format == "sarif-2.1.0") and
  ([.non_adapter[] | select(.id == "burp-suite-community")][0] |
    .execution == "manual-desktop" and
    .availability == "optional-desktop" and
    .official_url == "https://portswigger.net/burp/communitydownload" and
    (.automation_note | contains("not installed in the headless runner"))) and
  ([.validation[] | select(.id == "burp-suite-community")] | length) == 0
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

lifecycle_project_id="$(jq -r '.projects[] | select(.name == "Platform Lifecycle Validation") | .id' "$work_dir/projects-all.json" | head -n1)"
if [ -z "$lifecycle_project_id" ]; then
  lifecycle_project_id="$(curl --config "$curl_config" \
    -H 'Content-Type: application/json' -X POST "$base_url/projects" \
    -d '{"name":"Platform Lifecycle Validation","description":"Disposable local control-plane lifecycle fixture; never used for target scanning."}' \
    | jq -er '.id')"
fi
smoke_archived_project_id="$lifecycle_project_id"
curl --config "$curl_config" -H 'Content-Type: application/json' -X POST \
  "$base_url/projects/$lifecycle_project_id/archive" \
  -d '{"requested_by":"smoke-project-archive","confirmation":"ARCHIVE PROJECT"}' \
  > "$work_dir/project-archive.json"
jq -e --arg project_id "$lifecycle_project_id" '
  .id == $project_id and .status == "archived" and
  (.archived_at | type == "string") and .archived_by == "smoke-project-archive"
' "$work_dir/project-archive.json" >/dev/null
curl --config "$curl_config" "$base_url/projects" > "$work_dir/projects-active-after-archive.json"
jq -e --arg project_id "$lifecycle_project_id" '
  all(.projects[]; (.id | tostring) != $project_id)
' "$work_dir/projects-active-after-archive.json" >/dev/null
archived_write_status="$(curl --config "$curl_config" --no-fail -sS \
  -o "$work_dir/archived-write-denied.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' -X POST \
  "$base_url/projects/$lifecycle_project_id/targets" \
  -d '{"base_url":"http://127.0.0.1:65534/","allowed_hosts":["127.0.0.1"],"authorization_reference":"must-be-blocked","authorization_confirmed":true}')"
test "$archived_write_status" = "409"
jq -e '.detail | contains("archived and read-only")' "$work_dir/archived-write-denied.json" >/dev/null
curl --config "$curl_config" -H 'Content-Type: application/json' -X POST \
  "$base_url/projects/$lifecycle_project_id/restore" \
  -d '{"requested_by":"smoke-project-restore"}' \
  > "$work_dir/project-restore.json"
jq -e --arg project_id "$lifecycle_project_id" '
  .id == $project_id and .status == "active"
' "$work_dir/project-restore.json" >/dev/null
curl --config "$curl_config" "$base_url/projects/$lifecycle_project_id/audit-events" \
  > "$work_dir/project-lifecycle-audit.json"
jq -e --arg project_id "$lifecycle_project_id" '
  any(.events[]; .event_type == "project.archived" and .actor == "smoke-project-archive" and (.object_id | tostring) == $project_id) and
  any(.events[]; .event_type == "project.restored" and .actor == "smoke-project-restore" and (.object_id | tostring) == $project_id)
' "$work_dir/project-lifecycle-audit.json" >/dev/null
smoke_archived_project_id=""

if [ -n "$project_id" ]; then
  smoke_source_project_id="$project_id"
  python3 - "$work_dir/source-delete-fixture.zip" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1], "w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("README.txt", "Disposable local source-deletion smoke fixture.\n")
PY
  curl --config "$curl_config" -X POST \
    "$base_url/projects/$project_id/source-artifacts" \
    -F "archive=@$work_dir/source-delete-fixture.zip;type=application/zip" \
    -F 'requested_by=smoke-source-delete' \
    -F 'authorization_reference=local-disposable-smoke-fixture' \
    -F 'authorization_confirmed=true' \
    > "$work_dir/source-upload.json"
  smoke_source_artifact_id="$(jq -er '.id' "$work_dir/source-upload.json")"
  test -d "$platform_root/data/sources/$smoke_source_artifact_id"
  curl --config "$curl_config" \
    -H 'Content-Type: application/json' -X DELETE \
    "$base_url/projects/$project_id/source-artifacts/$smoke_source_artifact_id" \
    -d '{"requested_by":"smoke-source-delete","confirmation":"DELETE SOURCE ARCHIVE"}' \
    > "$work_dir/source-delete.json"
  jq -e --arg artifact_id "$smoke_source_artifact_id" '
    .id == $artifact_id and
    .status == "deleted" and
    .deleted_file_count == 1 and
    .storage_cleanup_complete == true
  ' "$work_dir/source-delete.json" >/dev/null
  test ! -e "$platform_root/data/sources/$smoke_source_artifact_id"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/source-artifacts" \
    > "$work_dir/source-artifacts-after-delete.json"
  jq -e --arg artifact_id "$smoke_source_artifact_id" '
    all(.artifacts[]; (.id | tostring) != $artifact_id)
  ' "$work_dir/source-artifacts-after-delete.json" >/dev/null
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/audit-events" \
    > "$work_dir/source-delete-audit.json"
  jq -e --arg artifact_id "$smoke_source_artifact_id" '
    any(.events[];
      .event_type == "source_artifact.deleted" and
      (.object_id | tostring) == $artifact_id and
      .actor == "smoke-source-delete")
  ' "$work_dir/source-delete-audit.json" >/dev/null
  smoke_source_artifact_id=""

  smoke_target_project_id="$project_id"
  curl --config "$curl_config" \
    -H 'Content-Type: application/json' -X POST \
    "$base_url/projects/$project_id/targets" \
    -d '{
      "base_url":"http://127.0.0.1:65535/",
      "allowed_hosts":["127.0.0.1"],
      "excluded_paths":["/logout"],
      "max_run_seconds":30,
      "allow_state_changing":false,
      "allow_third_party_services":false,
      "authorization_reference":"local-disposable-smoke-fixture",
      "authorization_confirmed":true
    }' > "$work_dir/target-create.json"
  smoke_target_id="$(jq -er '.id' "$work_dir/target-create.json")"
  curl --config "$curl_config" \
    -H 'Content-Type: application/json' -X DELETE \
    "$base_url/projects/$project_id/targets/$smoke_target_id" \
    -d '{"requested_by":"smoke-target-delete","confirmation":"DELETE AUTHORIZED TARGET"}' \
    > "$work_dir/target-delete.json"
  jq -e --arg target_id "$smoke_target_id" '
    .id == $target_id and .status == "deleted"
  ' "$work_dir/target-delete.json" >/dev/null
  curl --config "$curl_config" "$base_url/projects/$project_id/targets" \
    > "$work_dir/targets-after-delete.json"
  jq -e --arg target_id "$smoke_target_id" '
    all(.targets[]; (.id | tostring) != $target_id)
  ' "$work_dir/targets-after-delete.json" >/dev/null
  curl --config "$curl_config" "$base_url/projects/$project_id/audit-events" \
    > "$work_dir/target-delete-audit.json"
  jq -e --arg target_id "$smoke_target_id" '
    any(.events[];
      .event_type == "target.deleted" and
      (.object_id | tostring) == $target_id and
      .actor == "smoke-target-delete")
  ' "$work_dir/target-delete-audit.json" >/dev/null
  smoke_target_id=""
fi

local_project_id="$(jq -r '.projects[] | select(.name == "Local Runner Validation") | .id' "$work_dir/projects.json" | head -n1)"
if [ -n "$local_project_id" ]; then
  curl --config "$curl_config" "$base_url/projects/$local_project_id/targets" > "$work_dir/local-targets.json"
  jq -e '([.targets[] | has("testing_window_open") and has("testing_window_label")] | all)' "$work_dir/local-targets.json" >/dev/null
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
    "$base_url/projects/$project_id/imports/burp" \
    > "$work_dir/burp-imports.json"
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.imports | type == "array") and
    (.imports | length <= 500) and
    all(.imports[];
      ((keys | sort) == ([
        "authorization_reference", "created_at", "duplicate_count", "filename",
        "imported_count", "requested_by", "run_id", "sha256", "skipped_excluded",
        "skipped_out_of_scope", "status", "target", "target_id"
      ] | sort)) and
      (.filename | type == "string") and
      (.sha256 | type == "string") and
      (.authorization_reference | type == "string") and
      (.imported_count | type == "number") and
      (.skipped_out_of_scope | type == "number") and
      (.skipped_excluded | type == "number") and
      (.duplicate_count | type == "number")
    ) and
    (tostring | test("raw_request|raw_response|cookie|password|authorization: bearer"; "i") | not)
  ' "$work_dir/burp-imports.json" >/dev/null
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
    "$base_url/projects/$project_id/assessment-provenance" \
    > "$work_dir/assessment-provenance.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/role-coverage" \
    > "$work_dir/role-coverage.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/target-coverage" \
    > "$work_dir/target-coverage.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/source-coverage" \
    > "$work_dir/source-coverage.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/coverage-gaps" \
    > "$work_dir/coverage-gaps.json"
  curl --config "$curl_config" \
    "$base_url/projects/$project_id/coverage-gaps.json" \
    > "$work_dir/coverage-gaps-export.json"
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
    all(.findings[]; (.profile | type) == "string" and (.provenance == "supervised-run" or .provenance == "manual-import")) and
    all(.findings[]; (.credential_role == null or (.credential_role | type) == "string")) and
    (.coverage.adapter_gaps.unattempted_adapters | type == "array") and
    (.coverage.provenance.supervised_run_count | type == "number") and
    (.coverage.provenance.manual_import_run_count | type == "number") and
    (.coverage.provenance.supervised_tools | type == "array") and
    (.coverage.provenance.manual_import_sources | type == "array") and
    (.coverage.provenance.supervised_finding_count | type == "number") and
    (.coverage.provenance.manual_import_finding_count | type == "number") and
    (.coverage.supervised_completed_runs | type == "number") and
    (.coverage.supervised_sealed_runs | type == "number") and
    (.coverage.adapter_gaps.attempted_coverage_percent | type == "number") and
    (.coverage.role_coverage.profiles | type == "array") and
    (.coverage.role_coverage.summary.configured_profiles == (.coverage.role_coverage.profiles | length)) and
    (.coverage.target_coverage.targets | type == "array") and
    (.coverage.target_coverage.available_adapters | type == "array") and
    (.coverage.source_coverage.artifacts | type == "array") and
    (.coverage.source_coverage.available_adapters | type == "array") and
    (.coverage.coverage_gaps.status == "gaps-present" or .coverage.coverage_gaps.status == "no-recorded-gaps") and
    (.coverage.coverage_gaps.gap_count | type == "number") and
    (.coverage.coverage_gaps.gaps.unattempted_adapters | type == "array") and
    (.coverage.coverage_gaps.gaps.untested_targets | type == "array") and
    (.coverage.coverage_gaps.gaps.target_adapter_gaps | type == "array") and
    (.coverage.coverage_gaps.gaps.untested_sources | type == "array") and
    (.coverage.coverage_gaps.gaps.source_adapter_gaps | type == "array") and
    (.coverage.coverage_gaps.gaps.untested_roles | type == "array") and
    (.coverage.coverage_gaps.external_approval_required | type == "array") and
    (.coverage.coverage_gaps.external_approval_required_count == (.coverage.coverage_gaps.external_approval_required | length)) and
    (.coverage.coverage_gaps.disclaimer | contains("does not prove")) and
    all(.coverage.source_coverage.artifacts[];
      (.filename | type == "string") and
      (.sha256 | type == "string") and
      (.attempted_adapters | type == "array") and
      (.successful_adapters | type == "array") and
      (.unattempted_adapters | type == "array")
    ) and
    all(.coverage.target_coverage.targets[];
      (.attempted_adapters | type == "array") and
      (.successful_adapters | type == "array") and
      (.unattempted_adapters | type == "array")
    ) and
    all(.coverage.role_coverage.profiles[];
      (has("username") | not) and (has("password") | not)
    )
  ' "$work_dir/report.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.available_adapters | type == "array") and
    (.attempted_adapters | type == "array") and
    (.successful_adapters | type == "array") and
    (.unattempted_adapters | type == "array")
  ' "$work_dir/adapter-coverage.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.supervised_run_count | type == "number") and
    (.manual_import_run_count | type == "number") and
    (.supervised_tools | type == "array") and
    (.manual_import_sources | type == "array") and
    (.supervised_finding_count | type == "number") and
    (.manual_import_finding_count | type == "number")
  ' "$work_dir/assessment-provenance.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.profiles | type == "array") and
    (.summary.configured_profiles == (.profiles | length)) and
    (.summary.tested_coverage_percent | type == "number") and
    all(.profiles[];
      (.name | type == "string") and
      (.role_name | type == "string") and
      (.attempted_runs | type == "number") and
      (.successful_runs | type == "number") and
      (has("username") | not) and
      (has("password") | not)
    )
  ' "$work_dir/role-coverage.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.available_adapters | type == "array") and
    (.targets | type == "array") and
    all(.targets[];
      (.base_url | type == "string") and
      (.attempted_adapters | type == "array") and
      (.successful_adapters | type == "array") and
      (.unattempted_adapters | type == "array") and
      (.attempted_coverage_percent | type == "number") and
      (.successful_coverage_percent | type == "number")
    )
  ' "$work_dir/target-coverage.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.available_adapters | type == "array") and
    (.artifacts | type == "array") and
    all(.artifacts[];
      (.filename | type == "string") and
      (.sha256 | type == "string") and
      (.attempted_adapters | type == "array") and
      (.successful_adapters | type == "array") and
      (.unattempted_adapters | type == "array")
    )
  ' "$work_dir/source-coverage.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .project_id == $project_id and
    (.status == "gaps-present" or .status == "no-recorded-gaps") and
    (.gap_count | type == "number") and
    (.gaps.unattempted_adapters | type == "array") and
    (.gaps.attempted_without_success | type == "array") and
    (.gaps.untested_targets | type == "array") and
    (.gaps.targets_without_success | type == "array") and
    (.gaps.target_adapter_gaps | type == "array") and
    all(.gaps.target_adapter_gaps[]; (.unattempted_adapters | type == "array")) and
    (.gaps.untested_sources | type == "array") and
    (.gaps.sources_without_success | type == "array") and
    (.gaps.source_adapter_gaps | type == "array") and
    all(.gaps.source_adapter_gaps[]; (.unattempted_adapters | type == "array")) and
    (.gaps.untested_roles | type == "array") and
    (.gaps.roles_without_success | type == "array") and
    (.external_approval_required | type == "array") and
    (.external_approval_required_count == (.external_approval_required | length)) and
    all(.external_approval_required[]; . == "amass" or . == "spiderfoot" or . == "subfinder" or . == "theharvester") and
    (.disclaimer | contains("does not prove"))
  ' "$work_dir/coverage-gaps.json" >/dev/null
  jq -e --arg project_id "$project_id" '
    .schema == "security-platform-coverage-gaps/v1" and
    (.generated_at | type == "string") and
    .platform_version == "0.158.0" and
    .project_id == $project_id and
    (.status == "gaps-present" or .status == "no-recorded-gaps") and
    (.gap_count | type == "number") and
    (.gaps | type == "object") and
    (.external_approval_required | type == "array") and
    (.external_approval_required_count == (.external_approval_required | length)) and
    (tostring | contains("username") | not) and
    (tostring | contains("password") | not) and
    (tostring | contains("encrypted_secret") | not)
  ' "$work_dir/coverage-gaps-export.json" >/dev/null
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
  grep -q '^### Authenticated role coverage' "$work_dir/report.md"
  grep -q '^### Per-target adapter coverage' "$work_dir/report.md"
  grep -q '^### Per-source adapter coverage' "$work_dir/report.md"
  grep -q '^### Coverage gap rollup' "$work_dir/report.md"
  grep -q '^## Assessment coverage' "$work_dir/report.md"
  grep -q '^- Manual import runs:' "$work_dir/report.md"
  grep -q 'explicitly imported manual findings' "$work_dir/report.md"
  grep -q 'Manual imports are operator-supplied metadata' "$work_dir/report.md"
  grep -q '^- Limitation: .*does not prove' "$work_dir/report.md"
  grep -q '^- Unresolved adapters requiring separate third-party approval:' "$work_dir/report.md"
  grep -q '^- Targets with incomplete adapter coverage:' "$work_dir/report.md"
  grep -q '^- Source archives with incomplete adapter coverage:' "$work_dir/report.md"
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
  test "$(find "$work_dir/bundle" -maxdepth 1 -type f | wc -l)" = "7"
  jq -e '.schema == "security-platform-audit/v1"' "$work_dir/bundle/audit-events.json" >/dev/null
  jq -e '.schema == "security-platform-coverage-gaps/v1"' "$work_dir/bundle/coverage-gaps.json" >/dev/null
  jq -e '(.coverage.coverage_gaps.gap_count | type == "number")' "$work_dir/bundle/report.json" >/dev/null
  grep -q '^### Coverage gap rollup' "$work_dir/bundle/report.md"
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
