#!/usr/bin/env bash
set -euo pipefail

platform_root="${SECURITY_PLATFORM_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$platform_root"

echo "Validating Compose configuration"
docker compose config --quiet

echo "Building control-plane services"
docker compose build api runner

echo "Running adapter registry and contract checks"
docker compose run --rm --no-deps \
  -v "$platform_root/ops:/workspace/ops:ro" \
  -v "$platform_root/config:/workspace/config:ro" \
  -v "$platform_root/backend/app:/workspace/backend/app:ro" \
  api python /workspace/ops/validate-adapters.py

docker compose run --rm --no-deps \
  -v "$platform_root/backend/tests:/app/tests:ro" \
  api python -m unittest discover -s /app/tests -v

echo "Repository checks passed"
