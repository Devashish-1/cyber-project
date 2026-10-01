#!/usr/bin/env bash
set -euo pipefail

platform_dir=/home/killswitch/security-platform
status_file="$platform_dir/data/platform-health.json"
checked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
disk_percent="$(df --output=pcent / | tail -1 | tr -dc '0-9')"
available_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
available_mib="$((available_kib / 1024))"
docker_state="$(systemctl is-active docker || true)"
unhealthy="$(docker ps --filter health=unhealthy --format '{{.Names}}' | paste -sd, - || true)"
backup_state=ok

latest_backup="$(find "$platform_dir/backups" -name 'postgres-*.sql.gz' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)"
if [[ -z "$latest_backup" ]] || [[ $(find "$latest_backup" -mtime +2 -print 2>/dev/null) ]]; then
  backup_state=stale-or-missing
fi

overall=ok
if (( disk_percent >= 85 )) || (( available_mib < 1024 )) || [[ "$docker_state" != active ]] || [[ -n "$unhealthy" ]] || [[ "$backup_state" != ok ]]; then
  overall=warning
fi

jq -n \
  --arg checked_at "$checked_at" \
  --arg overall "$overall" \
  --arg docker "$docker_state" \
  --arg unhealthy "$unhealthy" \
  --arg backup "$backup_state" \
  --argjson disk_percent "$disk_percent" \
  --argjson available_memory_mib "$available_mib" \
  '{checked_at:$checked_at,status:$overall,disk_percent:$disk_percent,available_memory_mib:$available_memory_mib,docker:$docker,unhealthy_containers:$unhealthy,backup:$backup}' \
  > "$status_file.tmp"
mv "$status_file.tmp" "$status_file"

logger -t security-platform-health "status=$overall disk=${disk_percent}% memory=${available_mib}MiB docker=$docker_state unhealthy=${unhealthy:-none} backup=$backup_state"
[[ "$overall" == ok ]]

