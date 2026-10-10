#!/usr/bin/env bash
set -euo pipefail

umask 077
platform_dir=/home/killswitch/security-platform
backup_dir="$platform_dir/backups"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
database_name="postgres-$timestamp.sql.gz"
config_name="config-$timestamp.tar.gz"
artifacts_name="artifacts-$timestamp.tar.gz"
manifest_name="backup-$timestamp.sha256"

mkdir -p "$backup_dir"
cd "$platform_dir"

set -a
source ./.env
set +a

docker compose exec -T postgres \
  pg_dump --clean --if-exists --no-owner --no-privileges \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  | gzip -9 > "$backup_dir/$database_name"

tar --exclude="config/templates/nuclei-upstream" -czf "$backup_dir/$config_name" \
  compose.yaml config dashboard backend ops .env.example .gitignore README.md

# A run that is still active may be present, but only sealed run manifests are
# treated as authoritative evidence by the application after restoration.
tar -czf "$backup_dir/$artifacts_name" evidence data/sources

(
  cd "$backup_dir"
  sha256sum "$database_name" "$config_name" "$artifacts_name" > "$manifest_name"
)

chmod 600 "$backup_dir/$database_name" "$backup_dir/$config_name" \
  "$backup_dir/$artifacts_name" "$backup_dir/$manifest_name"

find "$backup_dir" -type f -mtime +14 -delete

