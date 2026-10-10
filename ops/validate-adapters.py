#!/usr/bin/env python3
"""Validate adapter registry invariants without importing the application."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "backend" / "app" / "main.py"
ADAPTERS_PATH = ROOT / "config" / "adapters.yaml"
VALID_INPUTS = {"target", "source"}
VALID_PROFILES = {"observe", "controlled-active", "extended-active", "source-assisted", "load-resilience"}
MEMORY_LIMIT = re.compile(r"^[1-9][0-9]*(?:[kmg])$", re.IGNORECASE)


def implemented_tools() -> set[str]:
    tree = ast.parse(MAIN_PATH.read_text(encoding="utf-8"), filename=str(MAIN_PATH))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(getattr(target, "id", None) == "RUNNER_IMPLEMENTED_TOOLS" for target in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, set) and all(isinstance(item, str) for item in value):
                return value
    raise ValueError("RUNNER_IMPLEMENTED_TOOLS literal set was not found")


def main() -> int:
    document = yaml.safe_load(ADAPTERS_PATH.read_text(encoding="utf-8")) or {}
    adapters = document.get("adapters") or {}
    implemented = implemented_tools()
    errors: list[str] = []

    missing = sorted(implemented - set(adapters))
    extra = sorted(set(adapters) - implemented)
    if missing:
        errors.append(f"implemented but not configured: {', '.join(missing)}")
    if extra:
        errors.append(f"configured but not implemented: {', '.join(extra)}")

    for tool_id in sorted(implemented & set(adapters)):
        adapter = adapters[tool_id]
        image = str(adapter.get("image") or "")
        input_type = str(adapter.get("input") or "target")
        profile = str(adapter.get("profile") or "")
        resources = adapter.get("resources") or {}
        timeout = adapter.get("timeout_seconds")

        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
            errors.append(f"{tool_id}: image must use an immutable sha256 digest")
        if input_type not in VALID_INPUTS:
            errors.append(f"{tool_id}: invalid input type {input_type!r}")
        if profile not in VALID_PROFILES:
            errors.append(f"{tool_id}: invalid profile {profile!r}")
        if not isinstance(timeout, int) or not 1 <= timeout <= 7200:
            errors.append(f"{tool_id}: timeout_seconds must be an integer from 1 to 7200")
        if not isinstance(resources.get("cpus"), (int, float)) or not 0 < resources["cpus"] <= 4:
            errors.append(f"{tool_id}: cpus must be greater than 0 and no more than 4")
        if not MEMORY_LIMIT.fullmatch(str(resources.get("memory") or "")):
            errors.append(f"{tool_id}: memory must be a positive k/m/g Docker limit")
        if not isinstance(resources.get("pids"), int) or not 1 <= resources["pids"] <= 1024:
            errors.append(f"{tool_id}: pids must be an integer from 1 to 1024")
        if not str(adapter.get("approval") or "").strip():
            errors.append(f"{tool_id}: approval policy is required")
        if not str(adapter.get("output") or "").strip():
            errors.append(f"{tool_id}: sanitized output declaration is required")

    if errors:
        print("Adapter validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Adapter validation OK: {len(implemented)} implemented and digest-pinned adapters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
