#!/usr/bin/env python3
"""Verify backed-up evidence and source content against restored DB baselines."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


SHA256 = re.compile(r"[0-9a-f]{64}")


def load_baselines(path: pathlib.Path) -> dict[str, str]:
    baselines: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        identifier, digest = line.split("\t", 1)
        if not identifier or not SHA256.fullmatch(digest):
            raise ValueError(f"Invalid baseline entry in {path.name}")
        baselines[identifier] = digest
    return baselines


def member_digest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    source = archive.extractfile(member)
    if source is None:
        raise ValueError(f"Archive member cannot be read: {member.name}")
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def verify_archive(
    archive_path: pathlib.Path,
    evidence_seals: dict[str, str],
    source_hashes: dict[str, str],
) -> dict[str, int]:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 100_000:
            raise ValueError("Artifact archive member count is unsafe")
        regular: dict[str, tarfile.TarInfo] = {}
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise ValueError(f"Unsafe archive member: {member.name}")
            if member.isfile():
                regular[member.name] = member

        verified_evidence_files = 0
        for run_id, expected_manifest_digest in evidence_seals.items():
            prefix = f"evidence/runs/{run_id}/"
            manifest_name = f"{prefix}integrity.json"
            manifest_member = regular.get(manifest_name)
            if manifest_member is None:
                raise ValueError(f"Sealed evidence manifest is missing: {run_id}")
            if member_digest(archive, manifest_member) != expected_manifest_digest:
                raise ValueError(f"Evidence manifest seal mismatch: {run_id}")
            source = archive.extractfile(manifest_member)
            if source is None:
                raise ValueError(f"Evidence manifest cannot be read: {run_id}")
            manifest = json.load(source)
            if (
                manifest.get("version") != 1
                or manifest.get("algorithm") != "sha256"
                or manifest.get("run_id") != run_id
                or not isinstance(manifest.get("files"), list)
            ):
                raise ValueError(f"Evidence manifest is invalid: {run_id}")
            expected_names: set[str] = set()
            for item in manifest["files"]:
                name = item.get("name") if isinstance(item, dict) else None
                if not isinstance(name, str) or not name or pathlib.PurePosixPath(name).name != name:
                    raise ValueError(f"Evidence manifest path is invalid: {run_id}")
                if name in expected_names or not SHA256.fullmatch(str(item.get("sha256") or "")):
                    raise ValueError(f"Evidence manifest entry is invalid: {run_id}/{name}")
                expected_names.add(name)
                member = regular.get(f"{prefix}{name}")
                if member is None or member.size != item.get("size"):
                    raise ValueError(f"Sealed evidence file is missing or changed: {run_id}/{name}")
                if member_digest(archive, member) != item["sha256"]:
                    raise ValueError(f"Sealed evidence digest mismatch: {run_id}/{name}")
            actual_names = {
                name.removeprefix(prefix)
                for name in regular
                if name.startswith(prefix) and "/" not in name.removeprefix(prefix)
                and name != manifest_name
            }
            if actual_names != expected_names:
                raise ValueError(f"Sealed evidence contains unmanifested files: {run_id}")
            verified_evidence_files += len(expected_names)

        verified_source_files = 0
        for artifact_id, expected_content_digest in source_hashes.items():
            prefix = f"data/sources/{artifact_id}/content/"
            entries: list[tuple[str, int, str]] = []
            for name, member in regular.items():
                if name.startswith(prefix):
                    relative = name.removeprefix(prefix)
                    if relative:
                        entries.append((relative, member.size, member_digest(archive, member)))
            if not entries:
                raise ValueError(f"Approved source content is missing: {artifact_id}")
            digest = hashlib.sha256()
            for relative, size, file_digest in sorted(entries):
                digest.update(f"{relative}\0{size}\0{file_digest}\n".encode("utf-8"))
            if digest.hexdigest() != expected_content_digest:
                raise ValueError(f"Approved source content seal mismatch: {artifact_id}")
            verified_source_files += len(entries)

    return {
        "sealed_runs_verified": len(evidence_seals),
        "sealed_evidence_files_verified": verified_evidence_files,
        "source_artifacts_verified": len(source_hashes),
        "source_files_verified": verified_source_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("evidence_seals", type=pathlib.Path)
    parser.add_argument("source_hashes", type=pathlib.Path)
    args = parser.parse_args()
    result = verify_archive(
        args.archive,
        load_baselines(args.evidence_seals),
        load_baselines(args.source_hashes),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
