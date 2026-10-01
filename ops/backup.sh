#!/usr/bin/env bash
set -euo pipefail

umask 077
platform_dir=/home/killswitch/security-platform
backup_dir="$platform_dir/backups"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$backup_dir"
cd "$platform_dir"

set -a
source ./.env
set +a

docker compose exec -T postgres \
  pg_dump --clean --if-exists --no-owner --no-privileges \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  | gzip -9 > "$backup_dir/postgres-$timestamp.sql.gz"

tar --exclude="config/templates/nuclei-upstream" -czf "$backup_dir/config-$timestamp.tar.gz" \
  compose.yaml config dashboard backend .env.example .gitignore README.md

find "$backup_dir" -type f -mtime +14 -delete

