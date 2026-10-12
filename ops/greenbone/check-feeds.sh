#!/usr/bin/env bash
set -euo pipefail

platform_root="${SECURITY_PLATFORM_ROOT:-/home/killswitch/security-platform}"
compose_file="$platform_root/ops/greenbone/upstream-compose.yaml"
probe_script="$platform_root/ops/greenbone/check-feeds.py"
secret_file="${GREENBONE_ADMIN_PASSWORD_FILE:-/home/killswitch/.config/security-platform/greenbone-admin-password}"
output_file="${GREENBONE_FEED_STATUS_FILE:-$platform_root/data/tmp/greenbone-feed-status.json}"

cd "$platform_root"
sha256sum -c ops/greenbone/upstream-compose.sha256 >/dev/null
test -s "$secret_file"
test "$(stat -c %a "$secret_file")" = "600"
mkdir -p "$(dirname "$output_file")"
tmp_file="$(mktemp "$(dirname "$output_file")/.greenbone-feed-status.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT

docker compose -f "$compose_file" run --rm --no-deps -T \
  --user root \
  --entrypoint python3 \
  -v "$secret_file:/run/secrets/greenbone_admin_password:ro" \
  -v "$probe_script:/opt/security-platform/check-feeds.py:ro" \
  gvm-tools /opt/security-platform/check-feeds.py > "$tmp_file"

jq -e '
  (.checked_at | type == "number") and
  (.feeds | type == "array") and
  (.feeds | length == 4) and
  ([.feeds[].type] | sort == ["CERT","GVMD_DATA","NVT","SCAP"]) and
  all(.feeds[]; (.name | type == "string") and (.version | test("^[0-9]{12}$")))
' "$tmp_file" >/dev/null
chmod 600 "$tmp_file"
mv -f "$tmp_file" "$output_file"
trap - EXIT
printf 'Greenbone feed metadata verified and sanitized: %s\n' "$output_file"