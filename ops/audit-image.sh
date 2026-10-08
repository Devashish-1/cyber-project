#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <local-image-reference>" >&2
  exit 2
fi

image="$1"
if [[ ! "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]]; then
  echo "Image reference contains unsupported characters" >&2
  exit 2
fi

platform_root="${SECURITY_PLATFORM_ROOT:-/home/killswitch/security-platform}"
output_root="${IMAGE_AUDIT_OUTPUT_ROOT:-$platform_root/data/exports/image-audits}"
cache_root="${TRIVY_CACHE_ROOT:-$platform_root/data/trivy-cache}"
trivy_image="aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
syft_image="anchore/syft@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02"

cd "$platform_root"
mkdir -p "$output_root" "$cache_root"
uid="$(id -u)"
gid="$(id -g)"
docker_gid="$(stat -c '%g' /var/run/docker.sock)"
image_id="$(docker image inspect "$image" --format '{{.Id}}')"
slug="$(printf '%s' "$image" | tr '/:@' '----' | tr -cd 'A-Za-z0-9._-')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
prefix="$output_root/${slug}-${stamp}"

printf 'Auditing %s (%s)\n' "$image" "$image_id"
docker run --rm --user "$uid:$gid" --group-add "$docker_gid" \
  -e HOME=/tmp \
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=128m,uid=$uid,gid=$gid,mode=1777" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$cache_root:/cache" -v "$output_root:/out" \
  "$trivy_image" image --cache-dir /cache --sbom-sources '' \
  --skip-version-check --scanners vuln --format json \
  --output "/out/$(basename "$prefix").trivy.json" "$image"

docker run --rm --user "$uid:$gid" --group-add "$docker_gid" \
  -e HOME=/tmp \
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=1g,uid=$uid,gid=$gid,mode=1777" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$output_root:/out" \
  "$syft_image" "$image" \
  -o "cyclonedx-json=/out/$(basename "$prefix").sbom.json"

jq -e '.Results | type == "array"' "$prefix.trivy.json" >/dev/null
jq -e '.bomFormat == "CycloneDX" and (.components | type == "array")' \
  "$prefix.sbom.json" >/dev/null
sha256sum "$prefix.sbom.json" "$prefix.trivy.json" > "$prefix.sha256"

jq '{
  critical: ([.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length),
  high: ([.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length),
  fixable_high: ([.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" and (.FixedVersion // "") != "")] | length)
}' "$prefix.trivy.json"
printf 'SBOM: %s\nVulnerability report: %s\nChecksums: %s\n' \
  "$prefix.sbom.json" "$prefix.trivy.json" "$prefix.sha256"
