#!/usr/bin/env bash
set -euo pipefail
trap 'echo "Restore validation failed at line $LINENO" >&2' ERR

cd /home/killswitch/security-platform
umask 077
mkdir -p data/tmp data/exports
exec 9>data/tmp/backup-restore-validation.lock
flock -n 9 || { echo 'Another restore validation is running' >&2; exit 1; }

container=security-platform-restore-test
status_file=data/tmp/backup-restore-validation.json
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
passed=false
backup_name=''
config_name=''
artifacts_name=''
manifest_name=''
evidence_seals_file="$(mktemp data/tmp/backup-evidence-seals.XXXXXX)"
source_hashes_file="$(mktemp data/tmp/backup-source-hashes.XXXXXX)"
cleanup() {
  rc=$?
  if [[ "$passed" != true ]] && docker inspect "$container" >/dev/null 2>&1; then
    docker logs --tail 100 "$container" 2>&1 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$evidence_seals_file" "$source_hashes_file"
  if [[ "$passed" != true ]]; then
    jq -nc --arg started "$started_at" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg backup "$backup_name" \
      --arg configuration "$config_name" --arg artifacts "$artifacts_name" --arg manifest "$manifest_name" \
      '{status:"failed",started_at:$started,finished_at:$finished,backup:$backup,configuration:$configuration,artifacts:$artifacts,manifest:$manifest}' > "$status_file"
    chmod 600 "$status_file"
  fi
  exit "$rc"
}
trap cleanup EXIT

backup_file="$(find backups -maxdepth 1 -type f -name 'postgres-*.sql.gz' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-)"
[[ -n "$backup_file" && -s "$backup_file" ]]
backup_name="$(basename "$backup_file")"
timestamp="${backup_name#postgres-}"
timestamp="${timestamp%.sql.gz}"
config_name="config-$timestamp.tar.gz"
artifacts_name="artifacts-$timestamp.tar.gz"
manifest_name="backup-$timestamp.sha256"
[[ -s "backups/$config_name" && -s "backups/$artifacts_name" && -s "backups/$manifest_name" ]]
gzip -t "$backup_file"

(
  cd backups
  sha256sum -c "$manifest_name"
)

python3 - "backups/$config_name" "backups/$artifacts_name" <<'PY'
import pathlib
import sys
import tarfile

for archive_name in sys.argv[1:]:
    with tarfile.open(archive_name, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 100_000:
            raise SystemExit(f"unsafe member count: {archive_name}")
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise SystemExit(f"unsafe archive member: {archive_name}: {member.name}")
PY

artifact_members="$(tar -tzf "backups/$artifacts_name" | wc -l)"
echo "Backup archives and checksums verified"

set -a
# shellcheck disable=SC1091
. ./.env
set +a
source_counts="$(docker compose exec -T postgres psql -At -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c \
  "SELECT (SELECT count(*) FROM projects)||','||(SELECT count(*) FROM targets)||','||(SELECT count(*) FROM runs)||','||(SELECT count(*) FROM observations);")"
echo "Source database counts captured"

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
  container_logs="$(docker logs "$container" 2>&1)"
  [[ "$container_logs" == *'PostgreSQL init process complete'* ]] && \
    docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null 2>&1 && break
  sleep 1
done
container_logs="$(docker logs "$container" 2>&1)"
[[ "$container_logs" == *'PostgreSQL init process complete'* ]]
docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null
echo "Isolated restore database is ready"
gzip -dc "$backup_file" | docker exec -i "$container" \
  psql -v ON_ERROR_STOP=1 -U postgres -d restore_test >/dev/null
echo "Database backup restored"

docker exec "$container" psql -At -F $'\t' -v ON_ERROR_STOP=1 -U postgres -d restore_test -c \
  "SELECT id::text, evidence_manifest_sha256 FROM runs WHERE evidence_manifest_sha256 IS NOT NULL ORDER BY id" \
  > "$evidence_seals_file"
docker exec "$container" psql -At -F $'\t' -v ON_ERROR_STOP=1 -U postgres -d restore_test -c \
  "SELECT id::text, content_sha256 FROM source_artifacts WHERE content_sha256 IS NOT NULL ORDER BY id" \
  > "$source_hashes_file"
artifact_validation="$(python3 ops/verify_artifact_backup.py \
  "backups/$artifacts_name" "$evidence_seals_file" "$source_hashes_file")"
echo "Evidence and source artifact baselines verified"

restore_counts="$(docker exec "$container" psql -At -v ON_ERROR_STOP=1 -U postgres -d restore_test -c \
  "SELECT (SELECT count(*) FROM projects)||','||(SELECT count(*) FROM targets)||','||(SELECT count(*) FROM runs)||','||(SELECT count(*) FROM observations);")"
[[ "$restore_counts" == "$source_counts" ]]

jq -nc --arg started "$started_at" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg backup "$backup_name" --arg configuration "$config_name" --arg artifacts "$artifacts_name" \
  --arg manifest "$manifest_name" --arg counts "$restore_counts" --arg artifact_members "$artifact_members" \
  --argjson artifact_validation "$artifact_validation" \
  '{status:"passed",started_at:$started,finished_at:$finished,backup:$backup,configuration:$configuration,artifacts:$artifacts,manifest:$manifest,checksums_verified:true,artifact_members:($artifact_members|tonumber),artifact_validation:$artifact_validation,tables:["projects","targets","runs","observations"],row_counts:($counts|split(",")|map(tonumber))}' \
  > "$status_file"
chmod 600 "$status_file"
passed=true
cat "$status_file" | jq .
