#!/usr/bin/env python3
"""Validate security invariants in normalized Docker Compose JSON."""

from __future__ import annotations

import json
import re
import sys


DIGEST_IMAGE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
HARDENED_SERVICES = {"api", "runner", "dashboard"}
REQUIRED_SERVICES = HARDENED_SERVICES | {"postgres", "redis"}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def volume_map(service: dict) -> dict[str, dict]:
    return {
        str(volume.get("target")): volume
        for volume in service.get("volumes") or []
        if isinstance(volume, dict) and volume.get("target")
    }


def main() -> int:
    document = json.load(sys.stdin)
    services = document.get("services") or {}
    errors: list[str] = []

    missing = sorted(REQUIRED_SERVICES - set(services))
    if missing:
        fail(errors, f"missing required services: {', '.join(missing)}")

    for name in sorted(REQUIRED_SERVICES & set(services)):
        service = services[name]
        build = service.get("build") or {}
        if build.get("network") == "host":
            fail(errors, f"{name}: host build networking is forbidden")

        ports = service.get("ports") or []
        if name == "dashboard":
            if len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1":
                fail(errors, "dashboard: exactly one IPv4 loopback publication is required")
        elif ports:
            fail(errors, f"{name}: published host ports are forbidden")

        if name not in {"api", "runner"}:
            image = str(service.get("image") or "")
            if not DIGEST_IMAGE.fullmatch(image):
                fail(errors, f"{name}: image must be pinned by sha256 digest")

    for name in sorted(HARDENED_SERVICES & set(services)):
        service = services[name]
        if service.get("read_only") is not True:
            fail(errors, f"{name}: root filesystem must be read-only")
        if "ALL" not in (service.get("cap_drop") or []):
            fail(errors, f"{name}: all Linux capabilities must be dropped")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            fail(errors, f"{name}: no-new-privileges must be enabled")
        tmpfs = service.get("tmpfs") or []
        tmp_entry = next((entry for entry in tmpfs if str(entry).startswith("/tmp:")), "")
        for option in ("nosuid", "nodev", "noexec", "size="):
            if option not in tmp_entry:
                fail(errors, f"{name}: /tmp tmpfs must include {option}")

    socket_owners = []
    for name, service in services.items():
        mounts = volume_map(service)
        if "/var/run/docker.sock" in mounts:
            socket_owners.append(name)
    if socket_owners != ["runner"]:
        fail(errors, "runner must be the only service mounting the Docker socket")

    expected_read_only = {
        "api": {"/app/config", "/evidence", "/image-audits", "/backups", "/validation"},
        "runner": {"/app/config", "/sources"},
        "dashboard": {"/usr/share/nginx/html", "/etc/nginx/conf.d/default.conf"},
    }
    for name, targets in expected_read_only.items():
        mounts = volume_map(services.get(name, {}))
        for target in sorted(targets):
            if not mounts.get(target, {}).get("read_only"):
                fail(errors, f"{name}: {target} must be mounted read-only")

    if errors:
        print("Compose security validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Compose security validation OK: private, pinned, least-privilege control plane")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
