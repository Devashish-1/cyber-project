#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
umask 077
mkdir -p data/tmp data/exports
exec 9>data/tmp/backup-restore-validation.lock
flock -n 9 || { echo 'Another restore validation is running' >&2; exit 1; }

container=security-platform-restore-test
status_file=data/exports/backup-restore-validation.json
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
passed=false
backup_name=''
cleanup() {
  rc=$?
  if [[ "$passed" != true ]] && docker inspect "$container" >/dev/null 2>&1; then
    docker logs --tail 100 "$container" 2>&1 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [[ "$passed" != true ]]; then
    jq -nc --arg started "$started_at" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg backup "$backup_name" \
      '{status:"failed",started_at:$started,finished_at:$finished,backup:$backup}' > "$status_file"
    chmod 600 "$status_file"
  fi
  exit "$rc"
}
trap cleanup EXIT

backup_file="$(find backups -maxdepth 1 -type f -name 'postgres-*.sql.gz' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-)"
[[ -n "$backup_file" && -s "$backup_file" ]]
backup_name="$(basename "$backup_file")"
gzip -t "$backup_file"

set -a
# shellcheck disable=SC1091
. ./.env
set +a
source_counts="$(docker compose exec -T postgres psql -At -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c \
  "SELECT (SELECT count(*) FROM projects)||','||(SELECT count(*) FROM targets)||','||(SELECT count(*) FROM runs)||','||(SELECT count(*) FROM observations);")"

postgres_image="$(docker inspect security-platform-postgres-1 --format '{{.Image}}')"
docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --name "$container" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 70:70 \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=1g,uid=70,gid=70,mode=0700 \
  --tmpfs /run/postgresql:rw,nosuid,nodev,size=16m,uid=70,gid=70,mode=0775 \
  -e POSTGRES_PASSWORD=restore-validation-only \
  -e POSTGRES_DB=restore_test \
  "$postgres_image" >/dev/null

for _ in $(seq 1 60); do
  docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null
gzip -dc "$backup_file" | docker exec -i "$container" \
  psql -v ON_ERROR_STOP=1 -U postgres -d restore_test >/dev/null

restore_counts="$(docker exec "$container" psql -At -v ON_ERROR_STOP=1 -U postgres -d restore_test -c \
  "SELECT (SELECT count(*) FROM projects)||','||(SELECT count(*) FROM targets)||','||(SELECT count(*) FROM runs)||','||(SELECT count(*) FROM observations);")"
[[ "$restore_counts" == "$source_counts" ]]

jq -nc --arg started "$started_at" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg backup "$backup_name" --arg counts "$restore_counts" \
  '{status:"passed",started_at:$started,finished_at:$finished,backup:$backup,tables:["projects","targets","runs","observations"],row_counts:($counts|split(",")|map(tonumber))}' \
  > "$status_file"
chmod 600 "$status_file"
passed=true
cat "$status_file" | jq .
