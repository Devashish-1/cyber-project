#!/usr/bin/env bash
set -euo pipefail

platform_dir=/home/killswitch/security-platform
status_file="$platform_dir/data/platform-health.json"
security_status_file="$platform_dir/data/tmp/deployment-security-status.json"
checked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
disk_percent="$(df --output=pcent / | tail -1 | tr -dc '0-9')"
available_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
available_mib="$((available_kib / 1024))"
docker_state="$(systemctl is-active docker || true)"
unhealthy="$(docker ps --filter health=unhealthy --format '{{.Names}}' | paste -sd, - || true)"
backup_state=ok

security_inspect="$(docker inspect \
  security-platform-api-1 security-platform-runner-1 security-platform-dashboard-1 \
  2>/dev/null || printf '[]')"
security_services="$(jq '[.[] | {
    service:(.Name | ltrimstr("/") | sub("^security-platform-"; "") | sub("-1$"; "")),
    read_only:(.HostConfig.ReadonlyRootfs == true),
    capabilities_dropped:((.HostConfig.CapDrop // []) | index("ALL") != null),
    no_new_privileges:((.HostConfig.SecurityOpt // []) | index("no-new-privileges:true") != null),
    non_root:((.Config.User // "") | test("^[1-9][0-9]*(:[0-9]+)?$")),
    running:(.State.Running == true),
    restart_count:.RestartCount
  }]' <<<"$security_inspect")"
security_enforced="$(jq -r 'length == 3 and all(.[]; .read_only and .capabilities_dropped and .no_new_privileges and .non_root and .running)' <<<"$security_services")"

latest_backup="$(find "$platform_dir/backups" -name 'postgres-*.sql.gz' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)"
if [[ -z "$latest_backup" ]] || [[ $(find "$latest_backup" -mtime +2 -print 2>/dev/null) ]]; then
  backup_state=stale-or-missing
fi

overall=ok
if (( disk_percent >= 85 )) || (( available_mib < 1024 )) || [[ "$docker_state" != active ]] || [[ -n "$unhealthy" ]] || [[ "$backup_state" != ok ]] || [[ "$security_enforced" != true ]]; then
  overall=warning
fi

jq -n \
  --arg checked_at "$checked_at" \
  --argjson enforced "$security_enforced" \
  --argjson services "$security_services" \
  '{checked_at:$checked_at,enforced:$enforced,services:$services}' \
  > "$security_status_file.tmp"
mv "$security_status_file.tmp" "$security_status_file"

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

logger -t security-platform-health "status=$overall disk=${disk_percent}% memory=${available_mib}MiB docker=$docker_state unhealthy=${unhealthy:-none} backup=$backup_state confinement=$security_enforced"
[[ "$overall" == ok ]]

