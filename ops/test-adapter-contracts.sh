#!/usr/bin/env bash
set -euo pipefail

platform_root="${SECURITY_PLATFORM_ROOT:-/home/killswitch/security-platform}"
cd "$platform_root"

docker compose run --rm --no-deps \
  -v "$platform_root/backend/tests:/app/tests:ro" \
  api python -m unittest discover -s /app/tests -v
