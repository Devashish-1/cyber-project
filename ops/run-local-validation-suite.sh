#!/usr/bin/env bash
set -euo pipefail

cd /home/killswitch/security-platform
mode="${1:-quick}"
if [[ "$mode" != quick && "$mode" != full ]]; then
  echo 'Usage: run-local-validation-suite.sh [quick|full]' >&2
  exit 2
fi

mkdir -p data/tmp logs/tools
exec 9>data/tmp/local-validation-suite.lock
if ! flock -n 9; then
  echo 'Another local validation suite is already running' >&2
  exit 1
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Local validation suite started: $started_at (mode=$mode)"

docker inspect -f '{{.State.Status}}' security-platform-local-lab | grep -Fxq running
docker inspect -f '{{.State.Status}}' security-platform-tls-lab | grep -Fxq running
docker compose ps --status running --services | grep -Fxq api
docker compose ps --status running --services | grep -Fxq runner

./ops/test-adapter-contracts.sh
./ops/smoke-test.sh
./ops/run-local-validation.sh whatweb
./ops/run-local-cancellation-validation.sh

if [[ "$mode" == full ]]; then
  ./ops/run-local-validation.sh testssl https://172.17.0.3:8443/
  ./ops/run-local-batch-validation.sh
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"started_at":"%s","finished_at":"%s","mode":"%s","status":"passed"}\n' \
  "$started_at" "$finished_at" "$mode" >data/tmp/local-validation-suite.json
chmod 600 data/tmp/local-validation-suite.json
echo "LOCAL VALIDATION SUITE PASSED ($mode)"
