import json
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import stat
import time
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
import redis
import yaml
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from cryptography.fernet import Fernet
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, HttpUrl

REGISTRY_PATH = Path(os.getenv("TOOL_REGISTRY_PATH", "/app/config/tools.yaml"))
ADAPTERS_PATH = Path(os.getenv("ADAPTERS_PATH", "/app/config/adapters.yaml"))
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
CONTROL_PLANE_TOKEN = os.environ["CONTROL_PLANE_TOKEN"]
if len(CONTROL_PLANE_TOKEN) < 32:
    raise RuntimeError("CONTROL_PLANE_TOKEN must contain at least 32 characters")
CREDENTIAL_ENCRYPTION_KEY = os.environ["CREDENTIAL_ENCRYPTION_KEY"].encode("ascii")
try:
    CREDENTIAL_CIPHER = Fernet(CREDENTIAL_ENCRYPTION_KEY)
except (TypeError, ValueError) as exc:
    raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key") from exc
RUN_QUEUE = "security-platform:runs"
RUNNER_HEARTBEAT = "security-platform:runner:heartbeat"
RUNNER_READINESS = "security-platform:runner:adapter-readiness"
RUNNER_RECOVERY = "security-platform:runner:recovery"
PLATFORM_PAUSE = "security-platform:control:paused"
RUNNER_IMPLEMENTED_TOOLS = {"arjun", "bandit", "brakeman", "checkov", "codeql", "dalfox", "dnsrecon", "dnsx", "feroxbuster", "ffuf", "gitleaks", "gobuster", "grype", "hadolint", "httpx", "katana", "kics", "kiterunner", "kubescape", "massdns", "naabu", "nikto", "njsscan", "nmap", "nuclei-reviewed", "osv-scanner", "playwright", "schemathesis", "semgrep", "shellcheck", "sqlmap-controlled", "subfinder", "syft", "testssl", "trivy", "trufflehog", "wapiti", "zap-passive", "zap-baseline", "zap-full"}
RUN_PLANS = {
    "observe": ["httpx", "testssl", "zap-baseline"],
    "authenticated-browser": ["httpx", "playwright"],
    "controlled-web": ["dnsx", "naabu", "nmap", "httpx", "playwright", "katana", "nuclei-reviewed", "nikto", "zap-baseline"],
    "extended-web": ["naabu", "nmap", "httpx", "katana", "arjun", "nuclei-reviewed", "nikto", "zap-baseline", "ffuf", "gobuster", "feroxbuster", "kiterunner", "wapiti", "sqlmap-controlled"],
}
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence/runs"))
SOURCE_ROOT = Path(os.getenv("SOURCE_ROOT", "/sources"))
MAX_SOURCE_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_SOURCE_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_SOURCE_FILES = 5_000
MAX_EVIDENCE_BYTES = 1_048_576
MAX_EVIDENCE_LINES = 200
MIN_STORAGE_FREE_BYTES = int(os.getenv("MIN_STORAGE_FREE_BYTES", str(10 * 1024**3)))
MAX_STORAGE_USED_PERCENT = float(os.getenv("MAX_STORAGE_USED_PERCENT", "90"))
MAX_PENDING_RUNS = int(os.getenv("MAX_PENDING_RUNS", "100"))
MAX_TOOL_OUTPUT_BYTES = int(os.getenv("MAX_TOOL_OUTPUT_BYTES", str(16 * 1024 * 1024)))
MAX_TOOL_LOG_BYTES = int(os.getenv("MAX_TOOL_LOG_BYTES", str(2 * 1024 * 1024)))
MAX_TOOL_LOG_LINES = int(os.getenv("MAX_TOOL_LOG_LINES", "20000"))
MAX_RUN_EVIDENCE_BYTES = int(os.getenv("MAX_RUN_EVIDENCE_BYTES", str(64 * 1024 * 1024)))
MAX_RUN_EVIDENCE_FILES = int(os.getenv("MAX_RUN_EVIDENCE_FILES", "32"))
if (
    MIN_STORAGE_FREE_BYTES < 0
    or not 1 <= MAX_STORAGE_USED_PERCENT <= 100
    or MAX_PENDING_RUNS < 1
    or not 1024 <= MAX_TOOL_OUTPUT_BYTES <= 64 * 1024 * 1024
    or not 1 <= MAX_TOOL_LOG_BYTES <= MAX_TOOL_OUTPUT_BYTES
    or not 1 <= MAX_TOOL_LOG_LINES <= 100_000
    or not MAX_TOOL_OUTPUT_BYTES <= MAX_RUN_EVIDENCE_BYTES <= 1024 * 1024 * 1024
    or not 4 <= MAX_RUN_EVIDENCE_FILES <= 256
):
    raise RuntimeError("Storage admission thresholds are invalid")
SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "token", "password", "secret", "api_key", "apikey"}


def init_database() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id UUID PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS targets (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    base_url TEXT NOT NULL,
                    allowed_hosts JSONB NOT NULL,
                    excluded_paths JSONB NOT NULL,
                    dns_resolver TEXT,
                    authorization_reference TEXT NOT NULL,
                    authorization_confirmed BOOLEAN NOT NULL CHECK (authorization_confirmed),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS dns_resolver TEXT;
                CREATE TABLE IF NOT EXISTS credential_profiles (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind = 'form-login'),
                    login_url TEXT NOT NULL,
                    username_selector TEXT NOT NULL,
                    password_selector TEXT NOT NULL,
                    submit_selector TEXT NOT NULL,
                    encrypted_secret BYTEA NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (project_id, name)
                );
                CREATE INDEX IF NOT EXISTS credential_profiles_project_created_idx
                    ON credential_profiles(project_id, created_at DESC);
                ALTER TABLE credential_profiles ADD COLUMN IF NOT EXISTS success_selector TEXT;
                CREATE TABLE IF NOT EXISTS runs (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    tool_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'cancelling', 'cancelled', 'succeeded', 'failed')),
                    requested_by TEXT NOT NULL,
                    error_message TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMPTZ,
                    finished_at TIMESTAMPTZ
                );
                CREATE TABLE IF NOT EXISTS run_batches (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    plan_id TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                ALTER TABLE run_batches ADD COLUMN IF NOT EXISTS credential_profile_id UUID
                    REFERENCES credential_profiles(id) ON DELETE RESTRICT;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS batch_id UUID;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS batch_step INTEGER;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS retest_of_observation UUID;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS evidence_manifest_sha256 TEXT;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS evidence_sealed_at TIMESTAMPTZ;
                CREATE INDEX IF NOT EXISTS runs_batch_step_idx
                    ON runs(batch_id, batch_step, created_at);
                CREATE INDEX IF NOT EXISTS runs_project_created_idx
                    ON runs(project_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS observations (
                    id UUID PRIMARY KEY,
                    run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                    observation_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
                    asset TEXT NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    fingerprint TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (run_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS observations_run_created_idx
                    ON observations(run_id, created_at);
                ALTER TABLE observations
                    ADD COLUMN IF NOT EXISTS review_status TEXT NOT NULL DEFAULT 'new';
                ALTER TABLE observations
                    ADD COLUMN IF NOT EXISTS review_notes TEXT NOT NULL DEFAULT '';
                ALTER TABLE observations
                    ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
                ALTER TABLE observations
                    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
                CREATE TABLE IF NOT EXISTS audit_events (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS audit_events_project_created_idx
                    ON audit_events(project_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS source_artifacts (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    compressed_size BIGINT NOT NULL,
                    extracted_size BIGINT NOT NULL,
                    file_count INTEGER NOT NULL,
                    authorization_reference TEXT NOT NULL,
                    authorization_confirmed BOOLEAN NOT NULL CHECK (authorization_confirmed),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS source_artifacts_project_created_idx
                    ON source_artifacts(project_id, created_at DESC);
                ALTER TABLE runs ALTER COLUMN target_id DROP NOT NULL;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS source_artifact_id UUID
                    REFERENCES source_artifacts(id) ON DELETE CASCADE;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS credential_profile_id UUID
                    REFERENCES credential_profiles(id) ON DELETE RESTRICT;
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'runs_exactly_one_input'
                    ) THEN
                        ALTER TABLE runs ADD CONSTRAINT runs_exactly_one_input CHECK (
                            (target_id IS NOT NULL AND source_artifact_id IS NULL)
                            OR (target_id IS NULL AND source_artifact_id IS NOT NULL)
                        );
                    END IF;
                END $$;
                CREATE OR REPLACE FUNCTION prevent_audit_event_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit events are append-only';
                END;
                $$ LANGUAGE plpgsql;
                DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
                CREATE TRIGGER audit_events_append_only
                    BEFORE UPDATE OR DELETE ON audit_events
                    FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
                """
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database()
    SOURCE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    yield


app = FastAPI(title="Security Testing Platform", version="0.75.0", lifespan=lifespan)


@app.middleware("http")
async def require_control_plane_token(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    supplied = request.headers.get("x-control-plane-token", "")
    if not secrets.compare_digest(supplied, CONTROL_PLANE_TOKEN):
        return JSONResponse(status_code=401, content={"detail": "Control-plane authentication required"})
    return await call_next(request)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)


class TargetCreate(BaseModel):
    base_url: HttpUrl
    allowed_hosts: list[str] = Field(min_length=1, max_length=50)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    dns_resolver: str | None = Field(default=None, max_length=80)
    authorization_reference: str = Field(min_length=3, max_length=500)
    authorization_confirmed: bool


class RunCreate(BaseModel):
    target_id: UUID | None = None
    source_artifact_id: UUID | None = None
    credential_profile_id: UUID | None = None
    tool_id: str = Field(min_length=1, max_length=100)
    profile: str = Field(min_length=1, max_length=100)
    requested_by: str = Field(min_length=2, max_length=120)
    approval_confirmed: bool


class CredentialProfileCreate(BaseModel):
    target_id: UUID
    name: str = Field(min_length=2, max_length=120)
    role_name: str = Field(min_length=2, max_length=120)
    kind: str = Field(default="form-login", pattern="^form-login$")
    login_url: HttpUrl
    username: str = Field(min_length=1, max_length=500)
    password: str = Field(min_length=1, max_length=4096)
    username_selector: str = Field(min_length=1, max_length=300)
    password_selector: str = Field(min_length=1, max_length=300)
    submit_selector: str = Field(min_length=1, max_length=300)
    success_selector: str | None = Field(default=None, min_length=1, max_length=300)
    requested_by: str = Field(min_length=2, max_length=120)


class CredentialProfileDelete(BaseModel):
    requested_by: str = Field(min_length=2, max_length=120)
    confirmation: str = Field(pattern="^DELETE CREDENTIAL PROFILE$")


class BatchCreate(BaseModel):
    target_id: UUID
    credential_profile_id: UUID | None = None
    plan_id: str = Field(pattern="^(observe|authenticated-browser|controlled-web|extended-web)$")
    requested_by: str = Field(min_length=2, max_length=120)
    approval_confirmed: bool


class ObservationReview(BaseModel):
    status: str = Field(pattern="^(new|confirmed|false_positive|accepted_risk|resolved)$")
    reviewed_by: str = Field(min_length=2, max_length=120)
    notes: str = Field(default="", max_length=2000)


class RetestCreate(BaseModel):
    requested_by: str = Field(min_length=2, max_length=120)
    approval_confirmed: bool


class EmergencyStopCreate(BaseModel):
    requested_by: str = Field(min_length=2, max_length=120)
    confirmation: str = Field(pattern="^STOP ALL RUNS$")


class PlatformResumeCreate(BaseModel):
    requested_by: str = Field(min_length=2, max_length=120)
    confirmation: str = Field(pattern="^RESUME NEW RUNS$")


def normalize_dns_resolver(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    candidate = value.strip()
    if candidate.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::([0-9]{1,5}))?", candidate)
        if not match:
            raise HTTPException(status_code=422, detail="DNS resolver must be an IP address with optional port")
        host, raw_port = match.groups()
    elif candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        host, raw_port = candidate.rsplit(":", 1)
    else:
        host, raw_port = candidate, None
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="DNS resolver must be an IP address, not a hostname") from exc
    port = int(raw_port or 53)
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=422, detail="DNS resolver port must be between 1 and 65535")
    formatted = f"[{address}]" if address.version == 6 else str(address)
    return f"{formatted}:{port}"


def load_registry() -> dict:
    with REGISTRY_PATH.open("r", encoding="utf-8") as registry_file:
        return yaml.safe_load(registry_file)


def load_adapters() -> dict:
    with ADAPTERS_PATH.open("r", encoding="utf-8") as adapters_file:
        return yaml.safe_load(adapters_file)


def queue_client() -> redis.Redis:
    return redis.from_url(REDIS_URL, socket_connect_timeout=3, decode_responses=True)


def record_audit(
    cursor: psycopg.Cursor,
    project_id: UUID,
    event_type: str,
    actor: str,
    object_type: str,
    object_id: object,
    details: dict | None = None,
) -> None:
    cursor.execute(
        """
        INSERT INTO audit_events
            (id, project_id, event_type, actor, object_type, object_id, details)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (uuid4(), project_id, event_type, actor, object_type, str(object_id), Jsonb(details or {})),
    )


def run_row(row: tuple) -> dict:
    return {
        "id": row[0],
        "project_id": row[1],
        "target_id": row[2],
        "tool_id": row[3],
        "profile": row[4],
        "status": row[5],
        "requested_by": row[6],
        "error_message": row[7],
        "created_at": row[8],
        "started_at": row[9],
        "finished_at": row[10],
        "retest_of_observation": row[11] if len(row) > 11 else None,
        "source_artifact_id": row[12] if len(row) > 12 else None,
        "credential_profile_id": row[13] if len(row) > 13 else None,
    }


def derive_batch_status(statuses: list[str]) -> str:
    if not statuses:
        return "empty"
    if any(status in {"running", "cancelling"} for status in statuses):
        return "running"
    if any(status == "queued" for status in statuses):
        return "queued"
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "cancelled" for status in statuses):
        return "cancelled"
    return "succeeded"


def sanitize_evidence(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else sanitize_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    return value


def storage_admission(*, enforce: bool = False) -> dict:
    disk = shutil.disk_usage(EVIDENCE_ROOT)
    used_percent = (disk.used / disk.total) * 100
    allowed = disk.free >= MIN_STORAGE_FREE_BYTES and used_percent < MAX_STORAGE_USED_PERCENT
    result = {
        "allowed": allowed,
        "free_bytes": disk.free,
        "minimum_free_bytes": MIN_STORAGE_FREE_BYTES,
        "used_percent": round(used_percent, 1),
        "maximum_used_percent": MAX_STORAGE_USED_PERCENT,
    }
    if enforce and not allowed:
        raise HTTPException(
            status_code=507,
            detail="Insufficient protected storage capacity; new work is temporarily blocked",
        )
    return result


def queue_admission(*, requested_slots: int = 0, enforce: bool = False) -> dict:
    cache = queue_client()
    pause_raw = cache.get(PLATFORM_PAUSE)
    try:
        pause = json.loads(pause_raw) if pause_raw else None
    except (json.JSONDecodeError, TypeError):
        pause = {"paused": True, "reason": "Invalid pause state requires operator review"}
    with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM runs WHERE status = 'queued'")
            database_queued = cursor.fetchone()[0]
    redis_queued = cache.llen(RUN_QUEUE)
    pending = max(database_queued, redis_queued)
    allowed = pause is None and pending + requested_slots <= MAX_PENDING_RUNS
    result = {
        "allowed": allowed,
        "pending": pending,
        "maximum_pending": MAX_PENDING_RUNS,
        "requested_slots": requested_slots,
        "available_slots": max(0, MAX_PENDING_RUNS - pending),
        "paused": pause is not None,
        "pause": pause,
    }
    if enforce and not allowed:
        if pause is not None:
            raise HTTPException(
                status_code=423,
                detail="Platform is paused by the emergency stop; explicit resume is required",
            )
        raise HTTPException(
            status_code=429,
            detail="Pending-run capacity is exhausted; wait for queued work to finish",
        )
    return result


def read_json_file(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_EVIDENCE_BYTES:
        return {}
    try:
        return sanitize_evidence(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}


def read_jsonl_file(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > MAX_EVIDENCE_BYTES:
        return []
    records = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if len(records) >= MAX_EVIDENCE_LINES:
                    break
                try:
                    records.append(sanitize_evidence(json.loads(line)))
                except json.JSONDecodeError:
                    records.append({"message": "Non-JSON output omitted"})
    except (UnicodeDecodeError, OSError):
        return []
    return records


def read_jsonl_since(path: Path, after: int) -> tuple[list[dict], int]:
    if not path.is_file():
        return [], after
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        return [{"event": "omitted", "reason": "Event stream exceeded the display limit"}], after
    records = []
    next_after = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if index < after:
                    next_after = index + 1
                    continue
                if len(records) >= MAX_EVIDENCE_LINES:
                    break
                next_after = index + 1
                try:
                    records.append(sanitize_evidence(json.loads(line)))
                except json.JSONDecodeError:
                    records.append({"event": "omitted", "reason": "Malformed event record"})
    except (UnicodeDecodeError, OSError):
        return [{"event": "unavailable", "reason": "Event stream could not be read"}], after
    return records, max(after, next_after)


def verify_evidence_integrity(
    run_id: UUID,
    run_directory: Path,
    expected_manifest_sha256: str | None,
    sealed_at: object,
) -> dict:
    if not expected_manifest_sha256:
        return {"status": "unsealed", "sealed_at": None, "files": 0}
    manifest_path = run_directory / "integrity.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise HTTPException(status_code=409, detail="Evidence integrity manifest is missing")
    try:
        encoded = manifest_path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != expected_manifest_sha256:
            raise HTTPException(status_code=409, detail="Evidence integrity manifest does not match its database seal")
        manifest = json.loads(encoded)
        if (
            manifest.get("version") != 1
            or manifest.get("algorithm") != "sha256"
            or manifest.get("run_id") != str(run_id)
            or not isinstance(manifest.get("files"), list)
        ):
            raise HTTPException(status_code=409, detail="Evidence integrity manifest is invalid")
        expected_names = set()
        for item in manifest["files"]:
            name = item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name or Path(name).name != name:
                raise HTTPException(status_code=409, detail="Evidence integrity manifest contains an invalid path")
            expected_names.add(name)
            path = run_directory / name
            if path.is_symlink() or not path.is_file():
                raise HTTPException(status_code=409, detail=f"Sealed evidence file is missing: {name}")
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if path.stat().st_size != item.get("size") or digest.hexdigest() != item.get("sha256"):
                raise HTTPException(status_code=409, detail=f"Sealed evidence file failed verification: {name}")
        actual_names = {
            path.name for path in run_directory.iterdir()
            if path.name != "integrity.json" and path.is_file() and not path.is_symlink()
        }
        if actual_names != expected_names:
            raise HTTPException(status_code=409, detail="Evidence directory contains unsealed files")
    except HTTPException:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise HTTPException(status_code=409, detail="Evidence integrity verification failed")
    return {"status": "verified", "sealed_at": sealed_at, "files": len(expected_names)}


@app.get("/health")
def health() -> dict[str, str]:
    with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

    cache = queue_client()
    cache.ping()
    return {"status": "ok", "database": "ok", "queue": "ok"}


@app.get("/platform-status")
def platform_status() -> dict:
    with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT status, COUNT(*)
                FROM runs
                WHERE status IN ('queued', 'running', 'cancelling')
                GROUP BY status
                """
            )
            counts = {status: count for status, count in cursor.fetchall()}

    cache = queue_client()
    heartbeat = cache.get(RUNNER_HEARTBEAT)
    heartbeat_age = max(0.0, time.time() - float(heartbeat)) if heartbeat else None
    runner = "ready" if heartbeat_age is not None and heartbeat_age <= 15 else "stale"
    readiness_raw = cache.get(RUNNER_READINESS)
    try:
        readiness = json.loads(readiness_raw) if readiness_raw else None
    except (json.JSONDecodeError, TypeError):
        readiness = None
    if isinstance(readiness, dict) and isinstance(readiness.get("checked_at"), (int, float)):
        readiness["age_seconds"] = round(max(0.0, time.time() - readiness["checked_at"]), 1)
    else:
        readiness = None
    recovery_raw = cache.get(RUNNER_RECOVERY)
    try:
        recovery = json.loads(recovery_raw) if recovery_raw else None
    except (json.JSONDecodeError, TypeError):
        recovery = None
    disk = shutil.disk_usage(EVIDENCE_ROOT)
    admission = storage_admission()
    redis_depth = cache.llen(RUN_QUEUE)
    queue_capacity = queue_admission()
    return {
        "runner": runner,
        "runner_heartbeat_age_seconds": round(heartbeat_age, 1) if heartbeat_age is not None else None,
        "adapter_readiness": readiness,
        "runner_recovery": recovery,
        "queue_depth": redis_depth,
        "runs": {
            "queued": counts.get("queued", 0),
            "running": counts.get("running", 0),
            "cancelling": counts.get("cancelling", 0),
        },
        "evidence_disk": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_percent": round((disk.used / disk.total) * 100, 1),
        },
        "storage_admission": admission,
        "queue_admission": queue_capacity,
        "capture_limits": {
            "max_output_bytes": MAX_TOOL_OUTPUT_BYTES,
            "max_log_bytes": MAX_TOOL_LOG_BYTES,
            "max_log_lines": MAX_TOOL_LOG_LINES,
            "max_run_evidence_bytes": MAX_RUN_EVIDENCE_BYTES,
            "max_run_evidence_files": MAX_RUN_EVIDENCE_FILES,
        },
        "credential_vault": {
            "configured": True,
            "cipher": "fernet",
            "plaintext_returned": False,
        },
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "security-testing-platform-api", "status": "ready"}


@app.post("/emergency-stop", status_code=202)
def emergency_stop(payload: EmergencyStopCreate) -> dict:
    cache = queue_client()
    pause = {
        "paused": True,
        "requested_by": payload.requested_by,
        "paused_at": time.time(),
        "reason": "Emergency stop",
    }
    cache.set(PLATFORM_PAUSE, json.dumps(pause, separators=(",", ":")))
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE runs SET
                    status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE 'cancelling' END,
                    finished_at = CASE WHEN status = 'queued' THEN NOW() ELSE finished_at END
                WHERE status IN ('queued', 'running')
                RETURNING id, project_id, status
                """
            )
            changed = cursor.fetchall()
            by_project: dict[UUID, list[dict]] = {}
            for run_id, project_id, status in changed:
                by_project.setdefault(project_id, []).append(
                    {"run_id": str(run_id), "status": status}
                )
            for project_id, project_runs in by_project.items():
                record_audit(
                    cursor, project_id, "platform.emergency_stop", payload.requested_by,
                    "platform", "all-runs", {"changed_runs": project_runs},
                )
            cursor.execute("SELECT id FROM projects")
            for (project_id,) in cursor.fetchall():
                if project_id not in by_project:
                    record_audit(
                        cursor, project_id, "platform.emergency_stop", payload.requested_by,
                        "platform", "all-runs", {"changed_runs": []},
                    )
    cache.delete(RUN_QUEUE)
    for run_id, _, _ in changed:
        cache.publish("security-platform:cancellations", str(run_id))
    return {
        "status": "paused",
        "pause": pause,
        "changed": [
            {"run_id": row[0], "project_id": row[1], "status": row[2]}
            for row in changed
        ],
    }


@app.post("/platform-resume")
def platform_resume(payload: PlatformResumeCreate) -> dict:
    cache = queue_client()
    previous_raw = cache.get(PLATFORM_PAUSE)
    cache.delete(PLATFORM_PAUSE)
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM projects")
            for (project_id,) in cursor.fetchall():
                record_audit(
                    cursor, project_id, "platform.resumed", payload.requested_by,
                    "platform", "all-runs", {"previous_pause_present": previous_raw is not None},
                )
    return {"status": "ready", "previous_pause_present": previous_raw is not None}


@app.get("/tools")
def tools() -> dict:
    registry = load_registry()
    return {"tools": registry["tools"]}


@app.get("/profiles")
def profiles() -> dict:
    registry = load_registry()
    return {"profiles": registry["profiles"]}


@app.get("/adapters")
def adapters() -> dict:
    configured = load_adapters().get("adapters", {})
    return {"adapters": {name: value for name, value in configured.items() if name in RUNNER_IMPLEMENTED_TOOLS}}


@app.get("/coverage")
def coverage() -> dict:
    registry = load_registry().get("tools", {})
    configured = load_adapters().get("adapters", {})
    eligible_modes = {"adapter", "approval-gated"}
    eligible = {
        name: metadata for name, metadata in registry.items()
        if metadata.get("execution") in eligible_modes
    }
    implemented_names = sorted(
        name for name in eligible
        if name in configured and name in RUNNER_IMPLEMENTED_TOOLS
    )
    pending_names = sorted(
        (name for name in eligible if name not in implemented_names),
        key=lambda name: (
            0 if eligible[name].get("availability") == "core" else 1,
            eligible[name].get("risk", ""),
            name,
        ),
    )
    by_category: dict[str, dict[str, int]] = {}
    for name, metadata in eligible.items():
        category = str(metadata.get("category") or "uncategorized")
        counts = by_category.setdefault(category, {"registered": 0, "implemented": 0})
        counts["registered"] += 1
        if name in implemented_names:
            counts["implemented"] += 1
    by_profile: dict[str, int] = {}
    by_input: dict[str, int] = {}
    for name in implemented_names:
        adapter = configured[name]
        profile = str(adapter.get("profile") or "unknown")
        input_type = str(adapter.get("input") or "target")
        by_profile[profile] = by_profile.get(profile, 0) + 1
        by_input[input_type] = by_input.get(input_type, 0) + 1
    eligible_count = len(eligible)
    implemented_count = len(implemented_names)
    by_execution: dict[str, int] = {}
    for metadata in registry.values():
        mode = str(metadata.get("execution") or "unspecified")
        by_execution[mode] = by_execution.get(mode, 0) + 1
    non_adapter = [
        {"id": name, **metadata}
        for name, metadata in sorted(registry.items())
        if metadata.get("execution") not in eligible_modes
    ]
    return {
        "totals": {
            "catalogued": len(registry),
            "adapter_eligible": eligible_count,
            "implemented": implemented_count,
            "pending": len(pending_names),
            "non_adapter": len(non_adapter),
            "coverage_percent": round((implemented_count / eligible_count) * 100, 1) if eligible_count else 0,
        },
        "by_profile": dict(sorted(by_profile.items())),
        "by_input": dict(sorted(by_input.items())),
        "by_execution": dict(sorted(by_execution.items())),
        "by_category": dict(sorted(by_category.items())),
        "pending": [
            {"id": name, **eligible[name]}
            for name in pending_names
        ],
        "non_adapter": non_adapter,
    }


@app.get("/run-plans")
def run_plans() -> dict:
    adapters = load_adapters().get("adapters", {})
    return {
        "plans": {
            plan_id: [
                {"tool_id": tool_id, "profile": adapters[tool_id]["profile"]}
                for tool_id in tool_ids
                if tool_id in adapters and tool_id in RUNNER_IMPLEMENTED_TOOLS
            ]
            for plan_id, tool_ids in RUN_PLANS.items()
        }
    }


@app.post("/projects", status_code=201)
def create_project(payload: ProjectCreate) -> dict:
    project_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO projects (id, name, description) VALUES (%s, %s, %s)",
                (project_id, payload.name, payload.description),
            )
            record_audit(cursor, project_id, "project.created", "system", "project", project_id, {"name": payload.name})
    return {"id": project_id, **payload.model_dump()}


@app.get("/projects")
def list_projects() -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, description, created_at FROM projects ORDER BY created_at DESC")
            rows = cursor.fetchall()
    return {
        "projects": [
            {"id": row[0], "name": row[1], "description": row[2], "created_at": row[3]}
            for row in rows
        ]
    }


@app.post("/projects/{project_id}/source-artifacts", status_code=201)
async def upload_source_artifact(
    project_id: UUID,
    archive: UploadFile = File(...),
    requested_by: str = Form(..., min_length=2, max_length=120),
    authorization_reference: str = Form(..., min_length=3, max_length=500),
    authorization_confirmed: bool = Form(...),
) -> dict:
    if not authorization_confirmed:
        raise HTTPException(status_code=422, detail="Explicit source authorization confirmation is required")
    storage_admission(enforce=True)
    filename = Path(archive.filename or "").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=422, detail="Only ZIP source archives are accepted")

    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")

    artifact_id = uuid4()
    artifact_root = SOURCE_ROOT / str(artifact_id)
    archive_path = artifact_root / "upload.zip"
    content_root = artifact_root / "content"
    artifact_root.mkdir(mode=0o700)
    digest = hashlib.sha256()
    compressed_size = 0
    extracted_size = 0
    file_count = 0
    try:
        with archive_path.open("xb") as destination:
            while chunk := await archive.read(1024 * 1024):
                compressed_size += len(chunk)
                if compressed_size > MAX_SOURCE_ARCHIVE_BYTES:
                    raise HTTPException(status_code=413, detail="Source archive exceeds 25 MiB limit")
                digest.update(chunk)
                destination.write(chunk)

        content_root.mkdir(mode=0o700)
        with zipfile.ZipFile(archive_path) as source_zip:
            for info in source_zip.infolist():
                member = PurePosixPath(info.filename)
                if (
                    not info.filename
                    or "\\" in info.filename
                    or member.is_absolute()
                    or ".." in member.parts
                    or (member.parts and ":" in member.parts[0])
                ):
                    raise HTTPException(status_code=422, detail="Archive contains an unsafe path")
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise HTTPException(status_code=422, detail="Archive symlinks are not accepted")
                if info.is_dir():
                    continue
                file_count += 1
                extracted_size += info.file_size
                if file_count > MAX_SOURCE_FILES:
                    raise HTTPException(status_code=413, detail="Archive exceeds 5,000-file limit")
                if extracted_size > MAX_SOURCE_EXTRACTED_BYTES:
                    raise HTTPException(status_code=413, detail="Expanded source exceeds 250 MiB limit")
                destination_path = content_root.joinpath(*member.parts)
                destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                actual_size = 0
                with source_zip.open(info) as source, destination_path.open("xb") as destination:
                    while chunk := source.read(1024 * 1024):
                        actual_size += len(chunk)
                        if actual_size > info.file_size or extracted_size - info.file_size + actual_size > MAX_SOURCE_EXTRACTED_BYTES:
                            raise HTTPException(status_code=413, detail="Expanded source exceeds declared limits")
                        destination.write(chunk)
                destination_path.chmod(0o600)
        archive_path.unlink()
        if file_count == 0:
            raise HTTPException(status_code=422, detail="Source archive contains no files")

        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO source_artifacts
                        (id, project_id, filename, sha256, compressed_size, extracted_size,
                         file_count, authorization_reference, authorization_confirmed)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                    """,
                    (
                        artifact_id, project_id, filename, digest.hexdigest(), compressed_size,
                        extracted_size, file_count, authorization_reference,
                    ),
                )
                record_audit(
                    cursor, project_id, "source_artifact.authorized", requested_by,
                    "source_artifact", artifact_id,
                    {"filename": filename, "sha256": digest.hexdigest(), "file_count": file_count},
                )
    except HTTPException:
        shutil.rmtree(artifact_root, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        shutil.rmtree(artifact_root, ignore_errors=True)
        raise HTTPException(status_code=422, detail="Invalid or unreadable ZIP archive") from exc
    finally:
        await archive.close()

    return {
        "id": artifact_id,
        "project_id": project_id,
        "filename": filename,
        "sha256": digest.hexdigest(),
        "compressed_size": compressed_size,
        "extracted_size": extracted_size,
        "file_count": file_count,
        "authorization_reference": authorization_reference,
    }


@app.get("/projects/{project_id}/source-artifacts")
def list_source_artifacts(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, filename, sha256, compressed_size, extracted_size,
                       file_count, authorization_reference, created_at
                FROM source_artifacts
                WHERE project_id = %s
                ORDER BY created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {
        "artifacts": [
            {
                "id": row[0], "filename": row[1], "sha256": row[2],
                "compressed_size": row[3], "extracted_size": row[4],
                "file_count": row[5], "authorization_reference": row[6],
                "created_at": row[7],
            }
            for row in rows
        ]
    }


@app.post("/projects/{project_id}/targets", status_code=201)
def create_target(project_id: UUID, payload: TargetCreate) -> dict:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Explicit target authorization confirmation is required")
    base_host = (payload.base_url.host or "").lower().rstrip(".")
    normalized_allowed_hosts = {host.lower().rstrip(".") for host in payload.allowed_hosts}
    if not base_host or base_host not in normalized_allowed_hosts:
        raise HTTPException(status_code=422, detail="Base URL host must be present in allowed_hosts")
    dns_resolver = normalize_dns_resolver(payload.dns_resolver)

    target_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                INSERT INTO targets
                    (id, project_id, base_url, allowed_hosts, excluded_paths, dns_resolver,
                     authorization_reference, authorization_confirmed)
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, TRUE)
                """,
                (
                    target_id,
                    project_id,
                    str(payload.base_url),
                    Jsonb(payload.allowed_hosts),
                    Jsonb(payload.excluded_paths),
                    dns_resolver,
                    payload.authorization_reference,
                ),
            )
            record_audit(
                cursor, project_id, "target.authorized", "system", "target", target_id,
                {
                    "base_url": str(payload.base_url),
                    "dns_resolver": dns_resolver,
                    "authorization_reference": payload.authorization_reference,
                },
            )
    return {
        "id": target_id,
        "project_id": project_id,
        **payload.model_dump(mode="json", exclude={"dns_resolver"}),
        "dns_resolver": dns_resolver,
    }


@app.get("/projects/{project_id}/targets")
def list_targets(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, base_url, allowed_hosts, excluded_paths, dns_resolver,
                       authorization_reference, authorization_confirmed, created_at
                FROM targets WHERE project_id = %s ORDER BY created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {
        "targets": [
            {
                "id": row[0], "base_url": row[1], "allowed_hosts": row[2],
                "excluded_paths": row[3], "dns_resolver": row[4],
                "authorization_reference": row[5],
                "authorization_confirmed": row[6], "created_at": row[7],
            }
            for row in rows
        ]
    }


def credential_profile_response(row: tuple) -> dict:
    return {
        "id": row[0], "project_id": row[1], "target_id": row[2],
        "name": row[3], "role_name": row[4], "kind": row[5],
        "login_url": row[6], "username_selector": row[7],
        "password_selector": row[8], "submit_selector": row[9],
        "success_selector": row[10], "created_at": row[11],
    }


@app.post("/projects/{project_id}/credential-profiles", status_code=201)
def create_credential_profile(project_id: UUID, payload: CredentialProfileCreate) -> dict:
    login_url = str(payload.login_url)
    parsed = urlsplit(login_url)
    login_host = (parsed.hostname or "").lower().rstrip(".")
    login_path = parsed.path or "/"
    if parsed.query or parsed.fragment:
        raise HTTPException(status_code=422, detail="Login URL must not contain a query or fragment")
    for selector in (payload.username_selector, payload.password_selector, payload.submit_selector, payload.success_selector):
        if selector is None:
            continue
        if any(ord(character) < 32 for character in selector):
            raise HTTPException(status_code=422, detail="Login selectors must not contain control characters")
    secret = json.dumps(
        {"username": payload.username, "password": payload.password},
        separators=(",", ":"),
    ).encode("utf-8")
    encrypted_secret = CREDENTIAL_CIPHER.encrypt(secret)
    profile_id = uuid4()
    try:
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT base_url, allowed_hosts, excluded_paths, authorization_confirmed
                    FROM targets WHERE id = %s AND project_id = %s
                    """,
                    (payload.target_id, project_id),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Target not found in project")
                target_host = (urlsplit(target[0]).hostname or "").lower().rstrip(".")
                allowed_hosts = {str(host).lower().rstrip(".") for host in target[1]}
                excluded_paths = ["/" + str(path).lstrip("/").rstrip("/") for path in target[2]]
                if not target[3]:
                    raise HTTPException(status_code=422, detail="Target authorization is not confirmed")
                if not login_host or login_host != target_host or login_host not in allowed_hosts:
                    raise HTTPException(status_code=422, detail="Login URL must use the authorized target host")
                if any(path == "/" or login_path == path or login_path.startswith(path + "/") for path in excluded_paths):
                    raise HTTPException(status_code=422, detail="Login URL is inside an excluded path")
                cursor.execute(
                    """
                    INSERT INTO credential_profiles
                        (id, project_id, target_id, name, role_name, kind, login_url,
                         username_selector, password_selector, submit_selector, success_selector, encrypted_secret)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id, project_id, target_id, name, role_name, kind, login_url,
                              username_selector, password_selector, submit_selector, success_selector, created_at
                    """,
                    (
                        profile_id, project_id, payload.target_id, payload.name.strip(),
                        payload.role_name.strip(), payload.kind, login_url,
                        payload.username_selector, payload.password_selector,
                        payload.submit_selector, payload.success_selector, encrypted_secret,
                    ),
                )
                row = cursor.fetchone()
                record_audit(
                    cursor, project_id, "credential_profile.created", payload.requested_by,
                    "credential_profile", profile_id,
                    {"target_id": str(payload.target_id), "name": payload.name.strip(), "role_name": payload.role_name.strip(), "kind": payload.kind},
                )
    except psycopg.errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="Credential profile name already exists in project") from exc
    return credential_profile_response(row)


@app.get("/projects/{project_id}/credential-profiles")
def list_credential_profiles(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, project_id, target_id, name, role_name, kind, login_url,
                       username_selector, password_selector, submit_selector, success_selector, created_at
                FROM credential_profiles WHERE project_id = %s ORDER BY created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {"profiles": [credential_profile_response(row) for row in rows]}


@app.delete("/credential-profiles/{profile_id}")
def delete_credential_profile(profile_id: UUID, payload: CredentialProfileDelete) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT project_id, name, role_name FROM credential_profiles WHERE id = %s FOR UPDATE",
                (profile_id,),
            )
            profile = cursor.fetchone()
            if profile is None:
                raise HTTPException(status_code=404, detail="Credential profile not found")
            cursor.execute("SELECT COUNT(*) FROM runs WHERE credential_profile_id = %s", (profile_id,))
            if cursor.fetchone()[0]:
                raise HTTPException(status_code=409, detail="Credential profile is referenced by run history and cannot be deleted")
            cursor.execute("DELETE FROM credential_profiles WHERE id = %s", (profile_id,))
            record_audit(
                cursor, profile[0], "credential_profile.deleted", payload.requested_by,
                "credential_profile", profile_id,
                {"name": profile[1], "role_name": profile[2]},
            )
    return {"id": profile_id, "deleted": True}


@app.post("/projects/{project_id}/runs", status_code=202)
def create_run(project_id: UUID, payload: RunCreate) -> dict:
    if not payload.approval_confirmed:
        raise HTTPException(status_code=422, detail="Explicit run approval is required")
    storage_admission(enforce=True)
    queue_admission(requested_slots=1, enforce=True)

    registry = load_registry()
    adapters = load_adapters().get("adapters", {})
    tool = registry.get("tools", {}).get(payload.tool_id)
    profile = registry.get("profiles", {}).get(payload.profile)
    adapter = adapters.get(payload.tool_id)

    if tool is None:
        raise HTTPException(status_code=422, detail="Unknown tool")
    if profile is None:
        raise HTTPException(status_code=422, detail="Unknown execution profile")
    if tool.get("execution") in {"disabled", "manual"}:
        raise HTTPException(status_code=422, detail="Tool is not available for automated execution")
    if adapter is None:
        raise HTTPException(status_code=422, detail="Tool adapter is not implemented yet")
    if payload.tool_id not in RUNNER_IMPLEMENTED_TOOLS:
        raise HTTPException(status_code=422, detail="Tool runner is not implemented yet")
    if adapter.get("profile") != payload.profile:
        raise HTTPException(status_code=422, detail="Tool is not approved for the selected profile")
    if payload.credential_profile_id is not None and payload.tool_id != "playwright":
        raise HTTPException(status_code=422, detail="Credential profiles are only supported by the Playwright adapter")
    input_type = adapter.get("input", "target")
    if input_type == "source":
        if payload.source_artifact_id is None or payload.target_id is not None:
            raise HTTPException(status_code=422, detail="This adapter requires exactly one source artifact")
    elif payload.target_id is None or payload.source_artifact_id is not None:
        raise HTTPException(status_code=422, detail="This adapter requires exactly one authorized target")

    run_id = uuid4()
    credential_role = None
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            if input_type == "source":
                cursor.execute(
                    "SELECT authorization_confirmed FROM source_artifacts WHERE id = %s AND project_id = %s",
                    (payload.source_artifact_id, project_id),
                )
                source = cursor.fetchone()
                if source is None:
                    raise HTTPException(status_code=404, detail="Source artifact not found in project")
                if not source[0]:
                    raise HTTPException(status_code=422, detail="Source authorization is not confirmed")
            else:
                cursor.execute(
                    "SELECT authorization_confirmed FROM targets WHERE id = %s AND project_id = %s",
                    (payload.target_id, project_id),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Target not found in project")
                if not target[0]:
                    raise HTTPException(status_code=422, detail="Target authorization is not confirmed")
                if payload.credential_profile_id is not None:
                    cursor.execute(
                        """
                        SELECT role_name FROM credential_profiles
                        WHERE id = %s AND project_id = %s AND target_id = %s
                        """,
                        (payload.credential_profile_id, project_id, payload.target_id),
                    )
                    credential = cursor.fetchone()
                    if credential is None:
                        raise HTTPException(status_code=404, detail="Credential profile not found for the selected target")
                    credential_role = credential[0]
            cursor.execute(
                """
                INSERT INTO runs
                    (id, project_id, target_id, source_artifact_id, credential_profile_id,
                     tool_id, profile, status, requested_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', %s)
                """,
                (
                    run_id, project_id, payload.target_id, payload.source_artifact_id, payload.credential_profile_id,
                    payload.tool_id, payload.profile, payload.requested_by,
                ),
            )
            record_audit(
                cursor, project_id, "run.approved", payload.requested_by, "run", run_id,
                {
                    "target_id": str(payload.target_id) if payload.target_id else None,
                    "source_artifact_id": str(payload.source_artifact_id) if payload.source_artifact_id else None,
                    "credential_profile_id": str(payload.credential_profile_id) if payload.credential_profile_id else None,
                    "credential_role": credential_role,
                    "tool_id": payload.tool_id, "profile": payload.profile,
                },
            )

    queue_client().rpush(RUN_QUEUE, str(run_id))
    return {"id": run_id, "status": "queued", **payload.model_dump(mode="json")}


@app.post("/projects/{project_id}/batches", status_code=202)
def create_batch(project_id: UUID, payload: BatchCreate) -> dict:
    if not payload.approval_confirmed:
        raise HTTPException(status_code=422, detail="Explicit batch approval is required")
    storage_admission(enforce=True)
    tool_ids = RUN_PLANS[payload.plan_id]
    if payload.credential_profile_id is not None and "playwright" not in tool_ids:
        raise HTTPException(status_code=422, detail="Selected workflow does not contain a Playwright step")
    queue_admission(requested_slots=len(tool_ids), enforce=True)
    registry = load_registry().get("tools", {})
    adapters = load_adapters().get("adapters", {})
    for tool_id in tool_ids:
        tool = registry.get(tool_id)
        adapter = adapters.get(tool_id)
        if tool is None or adapter is None or tool_id not in RUNNER_IMPLEMENTED_TOOLS:
            raise HTTPException(status_code=422, detail=f"Plan adapter is unavailable: {tool_id}")
        if tool.get("execution") in {"disabled", "manual"}:
            raise HTTPException(status_code=422, detail=f"Plan adapter cannot run automatically: {tool_id}")

    batch_id = uuid4()
    run_ids = [uuid4() for _ in tool_ids]
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT authorization_confirmed FROM targets WHERE id = %s AND project_id = %s",
                (payload.target_id, project_id),
            )
            target = cursor.fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found in project")
            if not target[0]:
                raise HTTPException(status_code=422, detail="Target authorization is not confirmed")
            credential_role = None
            if payload.credential_profile_id is not None:
                cursor.execute(
                    """
                    SELECT role_name FROM credential_profiles
                    WHERE id = %s AND project_id = %s AND target_id = %s
                    """,
                    (payload.credential_profile_id, project_id, payload.target_id),
                )
                credential = cursor.fetchone()
                if credential is None:
                    raise HTTPException(status_code=404, detail="Credential profile not found for the selected target")
                credential_role = credential[0]
            cursor.execute(
                """
                INSERT INTO run_batches
                    (id, project_id, target_id, credential_profile_id, plan_id, requested_by)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (batch_id, project_id, payload.target_id, payload.credential_profile_id, payload.plan_id, payload.requested_by),
            )
            cursor.executemany(
                """
                INSERT INTO runs
                    (id, project_id, target_id, credential_profile_id, tool_id, profile,
                     status, requested_by, batch_id, batch_step)
                VALUES (%s, %s, %s, %s, %s, %s, 'queued', %s, %s, %s)
                """,
                [
                    (
                        run_id, project_id, payload.target_id,
                        payload.credential_profile_id if tool_id == "playwright" else None, tool_id,
                        adapters[tool_id]["profile"], payload.requested_by, batch_id, batch_step,
                    )
                    for batch_step, (run_id, tool_id) in enumerate(zip(run_ids, tool_ids), start=1)
                ],
            )
            record_audit(
                cursor, project_id, "workflow.approved", payload.requested_by, "batch", batch_id,
                {
                    "target_id": str(payload.target_id), "plan_id": payload.plan_id, "tools": tool_ids,
                    "credential_profile_id": str(payload.credential_profile_id) if payload.credential_profile_id else None,
                    "credential_role": credential_role,
                },
            )

    queue = queue_client()
    queue.rpush(RUN_QUEUE, *[str(run_id) for run_id in run_ids])
    return {
        "id": batch_id,
        "status": "queued",
        "plan_id": payload.plan_id,
        "target_id": payload.target_id,
        "credential_profile_id": payload.credential_profile_id,
        "run_ids": run_ids,
        "tools": tool_ids,
    }


@app.get("/projects/{project_id}/batches")
def list_batches(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT b.id, b.target_id, b.plan_id, b.requested_by, b.created_at,
                       b.credential_profile_id,
                       COALESCE(array_agg(r.tool_id ORDER BY r.batch_step, r.created_at) FILTER (WHERE r.id IS NOT NULL), '{}'),
                       COALESCE(array_agg(r.status ORDER BY r.batch_step, r.created_at) FILTER (WHERE r.id IS NOT NULL), '{}')
                FROM run_batches b LEFT JOIN runs r ON r.batch_id = b.id
                WHERE b.project_id = %s
                GROUP BY b.id ORDER BY b.created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {
        "batches": [
            {
                "id": row[0], "target_id": row[1], "plan_id": row[2],
                "requested_by": row[3], "created_at": row[4], "credential_profile_id": row[5],
                "status": derive_batch_status(list(row[7])),
                "status_counts": {status: list(row[7]).count(status) for status in sorted(set(row[7]))},
                "runs": [
                    {"tool_id": tool_id, "status": status}
                    for tool_id, status in zip(row[6], row[7])
                ],
            }
            for row in rows
        ]
    }


@app.get("/batches/{batch_id}")
def get_batch(batch_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, project_id, target_id, plan_id, requested_by, created_at, credential_profile_id FROM run_batches WHERE id = %s",
                (batch_id,),
            )
            batch = cursor.fetchone()
            if batch is None:
                raise HTTPException(status_code=404, detail="Batch not found")
            cursor.execute(
                """
                SELECT id, project_id, target_id, tool_id, profile, status,
                       requested_by, error_message, created_at, started_at, finished_at,
                       retest_of_observation, source_artifact_id, credential_profile_id
                FROM runs WHERE batch_id = %s ORDER BY batch_step, created_at
                """,
                (batch_id,),
            )
            runs = [run_row(row) for row in cursor.fetchall()]
    return {
        "id": batch[0], "project_id": batch[1], "target_id": batch[2],
        "plan_id": batch[3], "requested_by": batch[4], "created_at": batch[5],
        "credential_profile_id": batch[6],
        "status": derive_batch_status([run["status"] for run in runs]), "runs": runs,
    }


@app.post("/batches/{batch_id}/cancel", status_code=202)
def cancel_batch(batch_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT project_id, requested_by FROM run_batches WHERE id = %s", (batch_id,))
            batch = cursor.fetchone()
            if batch is None:
                raise HTTPException(status_code=404, detail="Batch not found")
            cursor.execute(
                """
                UPDATE runs SET
                    status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE 'cancelling' END,
                    finished_at = CASE WHEN status = 'queued' THEN NOW() ELSE finished_at END
                WHERE batch_id = %s AND status IN ('queued', 'running')
                RETURNING id, status
                """,
                (batch_id,),
            )
            changed = cursor.fetchall()
            record_audit(
                cursor, batch[0], "workflow.cancel_requested", batch[1], "batch", batch_id,
                {"changed_runs": [{"run_id": str(row[0]), "status": row[1]} for row in changed]},
            )
    cache = queue_client()
    for run_id, _ in changed:
        cache.publish("security-platform:cancellations", str(run_id))
    return {"id": batch_id, "changed": [{"run_id": row[0], "status": row[1]} for row in changed]}


@app.get("/projects/{project_id}/runs")
def list_runs(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, project_id, target_id, tool_id, profile, status,
                       requested_by, error_message, created_at, started_at, finished_at,
                       retest_of_observation, source_artifact_id, credential_profile_id
                FROM runs WHERE project_id = %s ORDER BY created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {"runs": [run_row(row) for row in rows]}


@app.get("/runs/{run_id}")
def get_run(run_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, project_id, target_id, tool_id, profile, status,
                       requested_by, error_message, created_at, started_at, finished_at,
                       retest_of_observation, source_artifact_id, credential_profile_id
                FROM runs WHERE id = %s
                """,
                (run_id,),
            )
            row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run_row(row)


@app.get("/runs/{run_id}/events")
def get_run_events(run_id: UUID, after: int = 0) -> dict:
    if after < 0 or after > 100_000:
        raise HTTPException(status_code=422, detail="after must be between 0 and 100000")
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, tool_id, started_at, finished_at, error_message FROM runs WHERE id = %s",
                (run_id,),
            )
            row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    events, next_after = read_jsonl_since(EVIDENCE_ROOT / str(run_id) / "events.jsonl", after)
    terminal = row[0] in {"succeeded", "failed", "cancelled"}
    return {
        "run_id": run_id,
        "tool_id": row[1],
        "status": row[0],
        "terminal": terminal,
        "started_at": row[2],
        "finished_at": row[3],
        "error_message": row[4] if terminal else None,
        "events": events,
        "next_after": next_after,
        "limits": {"max_events_per_response": MAX_EVIDENCE_LINES},
    }


@app.post("/runs/{run_id}/cancel", status_code=202)
def cancel_run(run_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT status, project_id, requested_by FROM runs WHERE id = %s FOR UPDATE", (run_id,))
            row = cursor.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Run not found")
            if row[0] in {"cancelled", "succeeded", "failed"}:
                raise HTTPException(status_code=409, detail=f"Run is already {row[0]}")
            next_status = "cancelled" if row[0] == "queued" else "cancelling"
            cursor.execute(
                "UPDATE runs SET status = %s, finished_at = CASE WHEN %s = 'cancelled' THEN NOW() ELSE finished_at END WHERE id = %s",
                (next_status, next_status, run_id),
            )
            record_audit(
                cursor, row[1], "run.cancel_requested", row[2], "run", run_id,
                {"previous_status": row[0], "requested_status": next_status},
            )
    queue_client().publish("security-platform:cancellations", str(run_id))
    return {"id": run_id, "status": next_status}


@app.get("/runs/{run_id}/evidence")
def get_run_evidence(run_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, evidence_manifest_sha256, evidence_sealed_at FROM runs WHERE id = %s",
                (run_id,),
            )
            row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")

    run_directory = EVIDENCE_ROOT / str(run_id)
    integrity = verify_evidence_integrity(run_id, run_directory, row[1], row[2])
    return {
        "run_id": run_id,
        "status": row[0],
        "integrity": integrity,
        "metadata": read_json_file(run_directory / "metadata.json"),
        "events": read_jsonl_file(run_directory / "events.jsonl"),
        "output": read_jsonl_file(run_directory / "output.jsonl"),
        "limits": {"max_bytes_per_file": MAX_EVIDENCE_BYTES, "max_lines_per_file": MAX_EVIDENCE_LINES},
    }


@app.get("/projects/{project_id}/evidence-integrity")
def get_project_evidence_integrity(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, status, evidence_manifest_sha256, evidence_sealed_at
                FROM runs
                WHERE project_id = %s
                  AND status IN ('succeeded', 'failed', 'cancelled')
                ORDER BY created_at DESC
                """,
                (project_id,),
            )
            runs = cursor.fetchall()
    results = []
    counts = {"verified": 0, "unsealed": 0, "failed": 0}
    for run_id, status, manifest_digest, sealed_at in runs:
        try:
            integrity = verify_evidence_integrity(
                run_id,
                EVIDENCE_ROOT / str(run_id),
                manifest_digest,
                sealed_at,
            )
            integrity_status = integrity["status"]
            detail = None
        except HTTPException as exc:
            integrity_status = "failed"
            detail = str(exc.detail)
        counts[integrity_status] += 1
        results.append({
            "run_id": run_id,
            "run_status": status,
            "integrity_status": integrity_status,
            "sealed_at": sealed_at,
            "detail": detail,
        })
    return {
        "project_id": project_id,
        "counts": {**counts, "total": len(results)},
        "runs": results,
    }


@app.get("/runs/{run_id}/observations")
def get_run_observations(run_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT status FROM runs WHERE id = %s", (run_id,))
            run = cursor.fetchone()
            if run is None:
                raise HTTPException(status_code=404, detail="Run not found")
            cursor.execute(
                """
                SELECT id, observation_type, title, severity, asset, details, fingerprint, created_at,
                       review_status, review_notes, reviewed_by, reviewed_at
                FROM observations WHERE run_id = %s ORDER BY created_at, id
                """,
                (run_id,),
            )
            rows = cursor.fetchall()
    return {
        "run_id": run_id,
        "status": run[0],
        "observations": [
            {
                "id": row[0], "type": row[1], "title": row[2], "severity": row[3],
                "asset": row[4], "details": sanitize_evidence(row[5]),
                "fingerprint": row[6], "created_at": row[7],
                "review_status": row[8], "review_notes": row[9],
                "reviewed_by": row[10], "reviewed_at": row[11],
            }
            for row in rows
        ],
    }


@app.get("/runs/{run_id}/sbom")
def get_run_sbom(run_id: UUID) -> FileResponse:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT tool_id, status, evidence_manifest_sha256, evidence_sealed_at FROM runs WHERE id = %s",
                (run_id,),
            )
            run = cursor.fetchone()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if run[0] != "trivy":
        raise HTTPException(status_code=409, detail="This run does not produce an SBOM")
    sbom_path = EVIDENCE_ROOT / str(run_id) / "sbom.cdx.json"
    if not sbom_path.is_file():
        raise HTTPException(status_code=404, detail="SBOM is not available for this run")
    verify_evidence_integrity(run_id, sbom_path.parent, run[2], run[3])
    return FileResponse(
        sbom_path,
        media_type="application/vnd.cyclonedx+json",
        filename=f"security-platform-{run_id}-sbom.cdx.json",
    )


@app.get("/projects/{project_id}/findings")
def get_project_findings(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                WITH ranked AS (
                    SELECT o.id, o.run_id, r.tool_id, o.observation_type, o.title, o.severity,
                           o.asset, o.details, o.fingerprint, o.created_at, o.review_status,
                           o.review_notes, o.reviewed_by, o.reviewed_at,
                           COUNT(*) OVER (PARTITION BY o.fingerprint) AS occurrence_count,
                           MIN(o.created_at) OVER (PARTITION BY o.fingerprint) AS first_seen,
                           MAX(o.created_at) OVER (PARTITION BY o.fingerprint) AS last_seen,
                           ROW_NUMBER() OVER (
                               PARTITION BY o.fingerprint ORDER BY o.created_at DESC, o.id DESC
                           ) AS recency_rank
                    FROM observations o
                    JOIN runs r ON r.id = o.run_id
                    WHERE r.project_id = %s
                )
                SELECT id, run_id, tool_id, observation_type, title, severity, asset, details,
                       fingerprint, review_status, review_notes, reviewed_by, reviewed_at,
                       occurrence_count, first_seen, last_seen
                FROM ranked WHERE recency_rank = 1
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4 ELSE 5 END, last_seen DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {
        "project_id": project_id,
        "unique_count": len(rows),
        "findings": [
            {
                "id": row[0], "run_id": row[1], "tool_id": row[2], "type": row[3],
                "title": row[4], "severity": row[5], "asset": row[6],
                "details": sanitize_evidence(row[7]), "fingerprint": row[8],
                "review_status": row[9], "review_notes": row[10],
                "reviewed_by": row[11], "reviewed_at": row[12],
                "occurrence_count": row[13], "first_seen": row[14], "last_seen": row[15],
            }
            for row in rows
        ],
    }


@app.get("/projects/{project_id}/report.md", response_class=PlainTextResponse)
def get_project_report(project_id: UUID, include_info: bool = False) -> str:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT name, description, created_at FROM projects WHERE id = %s", (project_id,))
            project = cursor.fetchone()
            if project is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT base_url, allowed_hosts, excluded_paths, dns_resolver, authorization_reference
                FROM targets WHERE project_id = %s ORDER BY created_at
                """,
                (project_id,),
            )
            targets = cursor.fetchall()
            cursor.execute(
                """
                SELECT status, COUNT(*) FROM runs WHERE project_id = %s
                GROUP BY status ORDER BY status
                """,
                (project_id,),
            )
            status_counts = cursor.fetchall()
            cursor.execute(
                """
                SELECT DISTINCT tool_id FROM runs WHERE project_id = %s ORDER BY tool_id
                """,
                (project_id,),
            )
            tools = [row[0] for row in cursor.fetchall()]
            cursor.execute(
                """
                SELECT filename, sha256, file_count, compressed_size, extracted_size,
                       authorization_reference, created_at
                FROM source_artifacts WHERE project_id = %s ORDER BY created_at
                """,
                (project_id,),
            )
            sources = cursor.fetchall()
            cursor.execute(
                """
                SELECT tool_id, profile, status, COUNT(*),
                       COUNT(*) FILTER (WHERE evidence_manifest_sha256 IS NOT NULL),
                       MAX(finished_at)
                FROM runs WHERE project_id = %s
                GROUP BY tool_id, profile, status
                ORDER BY tool_id, profile, status
                """,
                (project_id,),
            )
            run_coverage = cursor.fetchall()
            cursor.execute(
                """
                SELECT COUNT(*) FILTER (WHERE status IN ('succeeded','failed','cancelled')),
                       COUNT(*) FILTER (
                           WHERE status IN ('succeeded','failed','cancelled')
                           AND evidence_manifest_sha256 IS NOT NULL
                       )
                FROM runs WHERE project_id = %s
                """,
                (project_id,),
            )
            completed_runs, sealed_runs = cursor.fetchone()

    finding_data = get_project_findings(project_id)
    findings = finding_data["findings"]
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]
    severity_counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }

    def md(value: object) -> str:
        return (
            str(value or "")
            .replace("\\", "\\\\")
            .replace("`", "\\`")
            .replace("|", "\\|")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\r", " ")
            .replace("\n", " ")
        )

    lines = [
        f"# Security assessment report — {md(project[0])}",
        "",
        f"Project ID: `{project_id}`  ",
        f"Generated: {datetime.now(timezone.utc).isoformat()}  ",
        f"Created: {project[2].isoformat()}  ",
        f"Description: {md(project[1]) or 'Not provided'}",
        "",
        "## Scope and authorization",
        "",
    ]
    if targets:
        for base_url, allowed_hosts, excluded_paths, dns_resolver, authorization_reference in targets:
            lines.extend([
                f"- Target: `{md(base_url)}`",
                f"  - Allowed hosts: {md(', '.join(allowed_hosts))}",
                f"  - Excluded paths: {md(', '.join(excluded_paths) or 'None recorded')}",
                f"  - Approved DNS resolver: {md(dns_resolver or 'None recorded')}",
                f"  - Authorization reference: {md(authorization_reference)}",
            ])
    else:
        lines.append("No targets recorded.")
    lines.extend(["", "### Authorized source archives", ""])
    if sources:
        for filename, sha256, file_count, compressed_size, extracted_size, authorization_reference, created_at in sources:
            lines.extend([
                f"- Source: `{md(filename)}` ({file_count} files, {extracted_size} extracted bytes)",
                f"  - SHA-256: `{md(sha256)}`",
                f"  - Archive size: {compressed_size} bytes",
                f"  - Authorization reference: {md(authorization_reference)}",
                f"  - Added: {created_at.isoformat()}",
            ])
    else:
        lines.append("No source archives recorded.")
    lines.extend([
        "",
        "## Automated coverage",
        "",
        f"- Tools executed: {md(', '.join(tools) or 'None')}",
        f"- Run outcomes: {md(', '.join(f'{status}={count}' for status, count in status_counts) or 'None')}",
        f"- Unique observations: {len(findings)}",
        f"- Severity totals: critical={severity_counts['critical']}, high={severity_counts['high']}, medium={severity_counts['medium']}, low={severity_counts['low']}, info={severity_counts['info']}",
        f"- Evidence sealed: {sealed_runs} of {completed_runs} completed runs",
        "",
        "### Run coverage matrix",
        "",
        "| Tool | Profile | Outcome | Runs | Sealed evidence | Latest completion |",
        "|---|---|---|---:|---:|---|",
    ])
    lines.extend(
        f"| {md(tool_id)} | {md(profile)} | {md(status)} | {count} | {sealed_count} | {latest.isoformat() if latest else '—'} |"
        for tool_id, profile, status, count, sealed_count, latest in run_coverage
    )
    if not run_coverage:
        lines.append("| — | — | No runs recorded | 0 | 0 | — |")
    lines.extend([
        "",
        "## Findings",
        "",
        "| Severity | Finding | Asset | Tool | Occurrences | Review status |",
        "|---|---|---|---|---:|---|",
    ])
    lines.extend(
        f"| {md(item['severity'])} | {md(item['title'])} | {md(item['asset'])} | {md(item['tool_id'])} | {item['occurrence_count']} | {md(item['review_status'])} |"
        for item in reported
    )
    if not reported:
        lines.append("| — | No reportable findings | — | — | 0 | — |")
    else:
        lines.extend(["", "### Finding details", ""])
        for index, item in enumerate(reported, start=1):
            details = json.dumps(sanitize_evidence(item["details"]), sort_keys=True, separators=(",", ":"), default=str)
            lines.extend([
                f"#### {index}. [{md(item['severity']).upper()}] {md(item['title'])}",
                "",
                f"- Asset: `{md(item['asset'])}`",
                f"- Tool: `{md(item['tool_id'])}`",
                f"- Evidence run: `{md(item['run_id'])}`",
                f"- Type: `{md(item['type'])}`",
                f"- Review status: {md(item['review_status'])}",
                f"- Occurrences: {item['occurrence_count']}",
                f"- First seen: {item['first_seen'].isoformat()}",
                f"- Last seen: {item['last_seen'].isoformat()}",
                f"- Review notes: {md(item['review_notes']) or 'None'}",
                f"- Sanitized details: `{md(details)}`",
                "",
            ])
    lines.extend([
        "",
        "## Limitations",
        "",
        "- This report covers automated adapters that actually ran; it is not proof that untested vulnerabilities are absent.",
        "- Business logic, authorization design, multi-step abuse, and exploit chains still require human testing.",
        "- Findings remain unverified until a reviewer confirms them; false positives and contextual severity changes are possible.",
        "- Evidence returned by the dashboard is sanitized and size-limited; restricted raw artifacts remain on the server.",
        "- Third-party services outside each saved target scope were not authorized or tested.",
        "",
        "Generated by Security Testing Platform.",
        "",
    ])
    return "\n".join(lines)


@app.get("/projects/{project_id}/audit-events")
def get_project_audit_events(project_id: UUID, limit: int = 100) -> dict:
    safe_limit = min(max(limit, 1), 500)
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, event_type, actor, object_type, object_id, details, created_at
                FROM audit_events WHERE project_id = %s
                ORDER BY created_at DESC, id DESC LIMIT %s
                """,
                (project_id, safe_limit),
            )
            rows = cursor.fetchall()
    return {
        "project_id": project_id,
        "events": [
            {
                "id": row[0], "event_type": row[1], "actor": row[2],
                "object_type": row[3], "object_id": row[4],
                "details": sanitize_evidence(row[5]), "created_at": row[6],
            }
            for row in rows
        ],
    }


@app.post("/observations/{observation_id}/retest", status_code=202)
def retest_observation(observation_id: UUID, payload: RetestCreate) -> dict:
    if not payload.approval_confirmed:
        raise HTTPException(status_code=422, detail="Explicit retest approval is required")
    storage_admission(enforce=True)
    queue_admission(requested_slots=1, enforce=True)
    run_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.project_id, r.target_id, r.source_artifact_id, r.credential_profile_id,
                       r.tool_id, r.profile,
                       COALESCE(t.authorization_confirmed, s.authorization_confirmed, FALSE)
                FROM observations o
                JOIN runs r ON r.id = o.run_id
                LEFT JOIN targets t ON t.id = r.target_id
                LEFT JOIN source_artifacts s ON s.id = r.source_artifact_id
                WHERE o.id = %s
                """,
                (observation_id,),
            )
            origin = cursor.fetchone()
            if origin is None:
                raise HTTPException(status_code=404, detail="Observation not found")
            project_id, target_id, source_artifact_id, credential_profile_id, tool_id, profile, input_authorized = origin
            registry_tool = load_registry().get("tools", {}).get(tool_id)
            adapter = load_adapters().get("adapters", {}).get(tool_id)
            if not input_authorized:
                raise HTTPException(status_code=422, detail="Input authorization is not confirmed")
            if registry_tool is None or adapter is None or tool_id not in RUNNER_IMPLEMENTED_TOOLS:
                raise HTTPException(status_code=422, detail="Original adapter is no longer available")
            if registry_tool.get("execution") in {"disabled", "manual"} or adapter.get("profile") != profile:
                raise HTTPException(status_code=422, detail="Original adapter policy no longer permits this retest")
            cursor.execute(
                """
                INSERT INTO runs
                    (id, project_id, target_id, source_artifact_id, credential_profile_id, tool_id, profile,
                     status, requested_by, retest_of_observation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', %s, %s)
                """,
                (
                    run_id, project_id, target_id, source_artifact_id, credential_profile_id, tool_id, profile,
                    payload.requested_by, observation_id,
                ),
            )
            record_audit(
                cursor, project_id, "finding.retest_approved", payload.requested_by,
                "observation", observation_id,
                {
                    "run_id": str(run_id),
                    "target_id": str(target_id) if target_id else None,
                    "source_artifact_id": str(source_artifact_id) if source_artifact_id else None,
                    "credential_profile_id": str(credential_profile_id) if credential_profile_id else None,
                    "tool_id": tool_id, "profile": profile,
                },
            )
    queue_client().rpush(RUN_QUEUE, str(run_id))
    return {
        "id": run_id, "status": "queued", "project_id": project_id,
        "target_id": target_id, "source_artifact_id": source_artifact_id,
        "credential_profile_id": credential_profile_id,
        "tool_id": tool_id, "profile": profile,
        "retest_of_observation": observation_id,
    }


@app.patch("/observations/{observation_id}")
def review_observation(observation_id: UUID, payload: ObservationReview) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.project_id, o.review_status
                FROM observations o JOIN runs r ON r.id = o.run_id
                WHERE o.id = %s
                """,
                (observation_id,),
            )
            observation = cursor.fetchone()
            if observation is None:
                raise HTTPException(status_code=404, detail="Observation not found")
            cursor.execute(
                """
                UPDATE observations
                SET review_status = %s, review_notes = %s, reviewed_by = %s, reviewed_at = NOW()
                WHERE id = %s
                RETURNING run_id, review_status, review_notes, reviewed_by, reviewed_at
                """,
                (payload.status, payload.notes, payload.reviewed_by, observation_id),
            )
            row = cursor.fetchone()
            record_audit(
                cursor, observation[0], "finding.reviewed", payload.reviewed_by,
                "observation", observation_id,
                {"previous_status": observation[1], "review_status": payload.status},
            )
    return {
        "id": observation_id, "run_id": row[0], "review_status": row[1],
        "review_notes": row[2], "reviewed_by": row[3], "reviewed_at": row[4],
    }
