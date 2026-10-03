#!/usr/bin/env bash
set -Eeuo pipefail

cd /home/killswitch/security-platform
mkdir -p docker/stacks/greenbone

printf '\n=== Downloading official Greenbone Community compose definition ===\n' \
  | tee logs/tools/install-greenbone-20261003.log
curl -fsSL https://greenbone.github.io/docs/latest/_static/compose.yaml \
  -o docker/stacks/greenbone/compose.yaml
sha256sum docker/stacks/greenbone/compose.yaml \
  | tee docker/stacks/greenbone/compose.yaml.sha256

printf '\n=== Greenbone image inventory ===\n'
docker compose -f docker/stacks/greenbone/compose.yaml config --images \
  | sort -u | tee docker/stacks/greenbone/images.txt

printf '\n=== Pulling Greenbone/OpenVAS images only; services will NOT start ===\n'
docker compose -f docker/stacks/greenbone/compose.yaml pull 2>&1 \
  | tee -a logs/tools/install-greenbone-20261003.log

printf '\n=== Verifying downloaded Greenbone images ===\n'
while IFS= read -r image; do
  docker image inspect "$image" \
    --format '{{index .RepoDigests 0}} | size={{.Size}}'
done < docker/stacks/greenbone/images.txt \
  | tee logs/tools/greenbone-images.txt

printf '\n=== Platform health and storage ===\n'
curl -fsS http://127.0.0.1:8080/api/health | jq .
docker system df
df -h /
