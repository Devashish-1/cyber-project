#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
mode="${1:-quick}"
if [[ "$mode" != quick && "$mode" != full && "$mode" != exhaustive ]]; then
  echo 'Usage: run-local-validation-suite.sh [quick|full|exhaustive]' >&2
  exit 2
fi

mkdir -p data/tmp logs/tools
exec 9>data/tmp/local-validation-suite.lock
if ! flock -n 9; then
  echo 'Another local validation suite is already running' >&2
  exit 1
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status_file=data/tmp/local-validation-suite.json
suite_passed=false
write_status() {
  local status="$1" finished_at="$2"
  if [[ -n "$finished_at" ]]; then
    printf '{"started_at":"%s","finished_at":"%s","mode":"%s","status":"%s"}\n' \
      "$started_at" "$finished_at" "$mode" "$status" >"$status_file"
  else
    printf '{"started_at":"%s","finished_at":null,"mode":"%s","status":"%s"}\n' \
      "$started_at" "$mode" "$status" >"$status_file"
  fi
  chmod 600 "$status_file"
}
finish_suite() {
  local rc=$? status=failed
  [[ "$suite_passed" == true ]] && status=passed
  write_status "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  return "$rc"
}
trap finish_suite EXIT
write_status running ''
echo "Local validation suite started: $started_at (mode=$mode)"

docker inspect -f '{{.State.Status}}' security-platform-local-lab | grep -Fxq running
docker inspect -f '{{.State.Status}}' security-platform-tls-lab | grep -Fxq running
docker compose ps --status running --services | grep -Fxq api
docker compose ps --status running --services | grep -Fxq runner

./ops/test-adapter-contracts.sh
./ops/smoke-test.sh
./ops/run-local-validation.sh whatweb
./ops/run-local-cancellation-validation.sh

if [[ "$mode" == full || "$mode" == exhaustive ]]; then
  ./ops/run-local-validation.sh testssl https://172.17.0.3:8443/
  ./ops/run-local-batch-validation.sh
  ./ops/run-local-target-adapter-validation.sh 'arjun,dalfox,feroxbuster,ffuf,gobuster,katana,kiterunner,naabu,nikto,nmap,nuclei-reviewed,sqlmap-controlled,wapiti,zap-baseline,zap-full'
  ./ops/run-local-remaining-adapter-validation.sh
  echo 'Subfinder runtime proof intentionally omitted: it requires an authorized domain and third-party provider opt-in.'
fi

if [[ "$mode" == exhaustive ]]; then
  ./ops/run-local-source-validation.sh
fi

suite_passed=true
echo "LOCAL VALIDATION SUITE PASSED ($mode)"
