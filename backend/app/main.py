import json
import hashlib
import gzip
import io
import ipaddress
import os
import re
import secrets
import shutil
import stat
import time
import tarfile
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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from cryptography.fernet import Fernet
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, HttpUrl, model_validator

REGISTRY_PATH = Path(os.getenv("TOOL_REGISTRY_PATH", "/app/config/tools.yaml"))
ADAPTERS_PATH = Path(os.getenv("ADAPTERS_PATH", "/app/config/adapters.yaml"))
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
CONTROL_PLANE_TOKEN = os.environ["CONTROL_PLANE_TOKEN"]
if len(CONTROL_PLANE_TOKEN) < 32:
    raise RuntimeError("CONTROL_PLANE_TOKEN must contain at least 32 characters")
CONTROL_PLANE_VIEWER_TOKEN = os.getenv("CONTROL_PLANE_VIEWER_TOKEN", "")
if CONTROL_PLANE_VIEWER_TOKEN and len(CONTROL_PLANE_VIEWER_TOKEN) < 32:
    raise RuntimeError("CONTROL_PLANE_VIEWER_TOKEN must contain at least 32 characters")
if CONTROL_PLANE_VIEWER_TOKEN and secrets.compare_digest(
    CONTROL_PLANE_VIEWER_TOKEN, CONTROL_PLANE_TOKEN
):
    raise RuntimeError("Operator and viewer control-plane tokens must differ")
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
RUNNER_IMPLEMENTED_TOOLS = {"amass", "arjun", "bandit", "brakeman", "checkov", "codeql", "dalfox", "dnsrecon", "dnsx", "feroxbuster", "ffuf", "gitleaks", "gobuster", "grype", "hadolint", "httpx", "katana", "kics", "kiterunner", "kubescape", "massdns", "naabu", "nikto", "njsscan", "nmap", "nuclei-reviewed", "osv-scanner", "playwright", "schemathesis", "semgrep", "shellcheck", "spiderfoot", "sqlmap-controlled", "subfinder", "syft", "testssl", "theharvester", "trivy", "trufflehog", "wapiti", "whatweb", "wpscan-passive", "zap-passive", "zap-baseline", "zap-full"}
RUN_PLANS = {
    "observe": ["httpx", "testssl", "zap-baseline"],
    "authenticated-browser": ["httpx", "playwright"],
    "controlled-web": ["dnsx", "naabu", "nmap", "httpx", "playwright", "katana", "nuclei-reviewed", "nikto", "zap-baseline"],
    "extended-web": ["naabu", "nmap", "httpx", "katana", "arjun", "nuclei-reviewed", "nikto", "zap-baseline", "ffuf", "gobuster", "feroxbuster", "kiterunner", "wapiti", "sqlmap-controlled"],
}
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence/runs"))
SOURCE_ROOT = Path(os.getenv("SOURCE_ROOT", "/sources"))
IMAGE_AUDIT_ROOT = Path(os.getenv("IMAGE_AUDIT_ROOT", "/image-audits"))
MAX_IMAGE_AUDIT_AGE_HOURS = int(os.getenv("MAX_IMAGE_AUDIT_AGE_HOURS", "168"))
BACKUP_ROOT = Path(os.getenv("BACKUP_ROOT", "/backups"))
BACKUP_RESTORE_STATUS_PATH = Path(os.getenv("BACKUP_RESTORE_STATUS_PATH", "/validation/backup-restore-validation.json"))
VALIDATION_STATUS_PATH = Path(os.getenv(
    "VALIDATION_STATUS_PATH",
    "/validation/local-validation-suite.json",
))
SOURCE_VALIDATION_STATUS_PATH = Path(os.getenv(
    "SOURCE_VALIDATION_STATUS_PATH",
    "/validation/local-source-validation.json",
))
DEPLOYMENT_SECURITY_STATUS_PATH = Path(os.getenv(
    "DEPLOYMENT_SECURITY_STATUS_PATH",
    "/validation/deployment-security-status.json",
))
MAX_BACKUP_AGE_HOURS = int(os.getenv("MAX_BACKUP_AGE_HOURS", "48"))
MAX_SOURCE_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_SOURCE_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_SOURCE_FILES = 5_000
MAX_EVIDENCE_BYTES = 1_048_576
MAX_EVIDENCE_LINES = 200
MIN_STORAGE_FREE_BYTES = int(os.getenv("MIN_STORAGE_FREE_BYTES", str(10 * 1024**3)))
MAX_STORAGE_USED_PERCENT = float(os.getenv("MAX_STORAGE_USED_PERCENT", "90"))
MAX_PENDING_RUNS = int(os.getenv("MAX_PENDING_RUNS", "100"))
MAX_RUNNER_READINESS_AGE_SECONDS = int(os.getenv("MAX_RUNNER_READINESS_AGE_SECONDS", "180"))
MAX_AUDIT_EXPORT_EVENTS = int(os.getenv("MAX_AUDIT_EXPORT_EVENTS", "10000"))
MAX_TOOL_OUTPUT_BYTES = int(os.getenv("MAX_TOOL_OUTPUT_BYTES", str(16 * 1024 * 1024)))
MAX_TOOL_LOG_BYTES = int(os.getenv("MAX_TOOL_LOG_BYTES", str(2 * 1024 * 1024)))
MAX_TOOL_LOG_LINES = int(os.getenv("MAX_TOOL_LOG_LINES", "20000"))
MAX_RUN_EVIDENCE_BYTES = int(os.getenv("MAX_RUN_EVIDENCE_BYTES", str(64 * 1024 * 1024)))
MAX_RUN_EVIDENCE_FILES = int(os.getenv("MAX_RUN_EVIDENCE_FILES", "32"))
if (
    MIN_STORAGE_FREE_BYTES < 0
    or not 1 <= MAX_STORAGE_USED_PERCENT <= 100
    or MAX_PENDING_RUNS < 1
    or not 100 <= MAX_AUDIT_EXPORT_EVENTS <= 100_000
    or not 1024 <= MAX_TOOL_OUTPUT_BYTES <= 64 * 1024 * 1024
    or not 1 <= MAX_TOOL_LOG_BYTES <= MAX_TOOL_OUTPUT_BYTES
    or not 1 <= MAX_TOOL_LOG_LINES <= 100_000
    or not MAX_TOOL_OUTPUT_BYTES <= MAX_RUN_EVIDENCE_BYTES <= 1024 * 1024 * 1024
    or not 4 <= MAX_RUN_EVIDENCE_FILES <= 256
    or not 1 <= MAX_IMAGE_AUDIT_AGE_HOURS <= 8760
    or not 1 <= MAX_BACKUP_AGE_HOURS <= 8760
):
    raise RuntimeError("Platform safety thresholds are invalid")
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
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS max_run_seconds INTEGER NOT NULL DEFAULT 300;
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS testing_window_start_minute_utc INTEGER;
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS testing_window_end_minute_utc INTEGER;
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS allow_state_changing BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE targets ADD COLUMN IF NOT EXISTS allow_third_party_services BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE targets
                    DROP CONSTRAINT IF EXISTS targets_valid_testing_window;
                ALTER TABLE targets
                    ADD CONSTRAINT targets_valid_testing_window CHECK (
                        (
                            testing_window_start_minute_utc IS NULL
                            AND testing_window_end_minute_utc IS NULL
                        )
                        OR (
                            testing_window_start_minute_utc IS NOT NULL
                            AND testing_window_end_minute_utc IS NOT NULL
                            AND testing_window_start_minute_utc BETWEEN 0 AND 1439
                            AND testing_window_end_minute_utc BETWEEN 0 AND 1439
                            AND testing_window_start_minute_utc
                                <> testing_window_end_minute_utc
                        )
                    );
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
                CREATE TABLE IF NOT EXISTS workflow_templates (
                    id UUID PRIMARY KEY,
                    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    tool_ids JSONB NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (project_id, name)
                );
                CREATE INDEX IF NOT EXISTS workflow_templates_project_created_idx
                    ON workflow_templates(project_id, created_at DESC);
                ALTER TABLE run_batches ADD COLUMN IF NOT EXISTS template_id UUID
                    REFERENCES workflow_templates(id) ON DELETE SET NULL;
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


app = FastAPI(title="Security Testing Platform", version="0.133.0", lifespan=lifespan)


def control_plane_role(supplied: str) -> str | None:
    if supplied and secrets.compare_digest(supplied, CONTROL_PLANE_TOKEN):
        return "operator"
    if (
        supplied
        and CONTROL_PLANE_VIEWER_TOKEN
        and secrets.compare_digest(supplied, CONTROL_PLANE_VIEWER_TOKEN)
    ):
        return "viewer"
    return None


def control_plane_role_allows(role: str, method: str) -> bool:
    return role == "operator" or method.upper() in {"GET", "HEAD", "OPTIONS"}


@app.middleware("http")
async def require_control_plane_token(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    supplied = request.headers.get("x-control-plane-token", "")
    role = control_plane_role(supplied)
    if role is None:
        return JSONResponse(status_code=401, content={"detail": "Control-plane authentication required"})
    if not control_plane_role_allows(role, request.method):
        return JSONResponse(status_code=403, content={"detail": "Viewer role is read-only"})
    request.state.control_plane_role = role
    return await call_next(request)


@app.get("/session")
def session(request: Request) -> dict:
    role = request.state.control_plane_role
    return {
        "role": role,
        "read_only": role == "viewer",
        "permissions": ["read"] if role == "viewer" else ["read", "operate"],
    }


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)


class TargetCreate(BaseModel):
    base_url: HttpUrl
    allowed_hosts: list[str] = Field(min_length=1, max_length=50)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    dns_resolver: str | None = Field(default=None, max_length=80)
    max_run_seconds: int = Field(default=300, ge=30, le=7200)
    testing_window_start_minute_utc: int | None = Field(default=None, ge=0, le=1439)
    testing_window_end_minute_utc: int | None = Field(default=None, ge=0, le=1439)
    allow_state_changing: bool = False
    allow_third_party_services: bool = False
    authorization_reference: str = Field(min_length=3, max_length=500)
    authorization_confirmed: bool

    @model_validator(mode="after")
    def validate_testing_window(self):
        start = self.testing_window_start_minute_utc
        end = self.testing_window_end_minute_utc
        if (start is None) != (end is None):
            raise ValueError("Testing window requires both UTC start and end times")
        if start is not None and start == end:
            raise ValueError("Testing window start and end must differ")
        return self


class TargetUpdate(TargetCreate):
    requested_by: str = Field(min_length=2, max_length=120)


def testing_window_allows(
    start_minute_utc: int | None,
    end_minute_utc: int | None,
    now: datetime | None = None,
) -> bool:
    if start_minute_utc is None and end_minute_utc is None:
        return True
    if (
        start_minute_utc is None
        or end_minute_utc is None
        or not 0 <= start_minute_utc <= 1439
        or not 0 <= end_minute_utc <= 1439
        or start_minute_utc == end_minute_utc
    ):
        return False
    current = now or datetime.now(timezone.utc)
    current_minute = current.hour * 60 + current.minute
    if start_minute_utc < end_minute_utc:
        return start_minute_utc <= current_minute < end_minute_utc
    return current_minute >= start_minute_utc or current_minute < end_minute_utc


def require_open_testing_window(
    start_minute_utc: int | None,
    end_minute_utc: int | None,
) -> None:
    if not testing_window_allows(start_minute_utc, end_minute_utc):
        raise HTTPException(
            status_code=409,
            detail="Target testing window is currently closed (UTC)",
        )


def require_state_changing_permission(
    profile: str,
    allow_state_changing: bool,
    *,
    workflow: bool = False,
) -> None:
    if profile == "extended-active" and not allow_state_changing:
        subject = "workflow steps" if workflow else "tests"
        raise HTTPException(
            status_code=409,
            detail=f"Target does not authorize state-changing extended-active {subject}",
        )


def require_third_party_service_permission(
    uses_third_party_services: bool,
    allow_third_party_services: bool,
    *,
    workflow: bool = False,
) -> None:
    if uses_third_party_services and not allow_third_party_services:
        subject = "workflow steps" if workflow else "test"
        raise HTTPException(
            status_code=409,
            detail=f"Target does not authorize third-party intelligence/provider access for this {subject}",
        )


def format_testing_window(start_minute_utc: int | None, end_minute_utc: int | None) -> str:
    if start_minute_utc is None and end_minute_utc is None:
        return "Any time"
    if start_minute_utc is None or end_minute_utc is None:
        return "Invalid configuration"
    start = f"{start_minute_utc // 60:02d}:{start_minute_utc % 60:02d}"
    end = f"{end_minute_utc // 60:02d}:{end_minute_utc % 60:02d}"
    suffix = " (overnight)" if start_minute_utc > end_minute_utc else ""
    return f"{start}-{end} UTC{suffix}"


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
    plan_id: str | None = Field(default=None, pattern="^(observe|authenticated-browser|controlled-web|extended-web)$")
    tool_ids: list[str] | None = Field(default=None, min_length=1, max_length=20)
    template_id: UUID | None = None
    requested_by: str = Field(min_length=2, max_length=120)
    approval_confirmed: bool


class WorkflowTemplateCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tool_ids: list[str] = Field(min_length=1, max_length=20)
    created_by: str = Field(min_length=2, max_length=120)


class WorkflowTemplateDelete(BaseModel):
    requested_by: str = Field(min_length=2, max_length=120)
    confirmation: str = Field(pattern="^DELETE WORKFLOW TEMPLATE$")


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


def normalize_target_policy(payload: TargetCreate) -> tuple[str, set[str], str | None]:
    base_host = (payload.base_url.host or "").lower().rstrip(".")
    allowed_hosts = {
        str(host).strip().lower().rstrip(".") for host in payload.allowed_hosts
        if str(host).strip()
    }
    if not base_host or base_host not in allowed_hosts:
        raise HTTPException(status_code=422, detail="Base URL host must be present in allowed_hosts")
    return base_host, allowed_hosts, normalize_dns_resolver(payload.dns_resolver)


def target_path_is_excluded(path: str, excluded_paths: list[str]) -> bool:
    normalized_path = "/" + str(path or "/").lstrip("/")
    normalized_path = normalized_path.rstrip("/") or "/"
    for excluded_path in excluded_paths:
        blocked = "/" + str(excluded_path).lstrip("/")
        blocked = blocked.rstrip("/") or "/"
        if blocked == "/" or normalized_path == blocked or normalized_path.startswith(blocked + "/"):
            return True
    return False


def validate_workflow_tool_ids(tool_ids: list[str]) -> dict:
    if len(tool_ids) != len(set(tool_ids)):
        raise HTTPException(status_code=422, detail="Custom workflows cannot contain duplicate adapters")
    registry = load_registry().get("tools", {})
    adapters = load_adapters().get("adapters", {})
    for tool_id in tool_ids:
        tool = registry.get(tool_id)
        adapter = adapters.get(tool_id)
        if tool is None or adapter is None or tool_id not in RUNNER_IMPLEMENTED_TOOLS:
            raise HTTPException(status_code=422, detail=f"Workflow adapter is unavailable: {tool_id}")
        if tool.get("execution") in {"disabled", "manual"}:
            raise HTTPException(status_code=422, detail=f"Workflow adapter cannot run automatically: {tool_id}")
        if adapter.get("input", "target") != "target":
            raise HTTPException(status_code=422, detail=f"Target workflows cannot contain source adapter: {tool_id}")
    return adapters


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


def sarif_review_metadata(finding: dict) -> tuple[dict, dict]:
    status = str(finding.get("review_status") or "new")
    notes = str(finding.get("review_notes") or "")
    reviewed_by = finding.get("reviewed_by")
    reviewed_at = finding.get("reviewed_at")
    properties = {
        "reviewStatus": status,
        "reviewNotes": notes,
        "reviewedBy": str(reviewed_by or ""),
        "reviewedAt": str(reviewed_at or ""),
    }
    lifecycle: dict = {}
    if status == "new":
        lifecycle["baselineState"] = "new"
    elif status == "confirmed":
        lifecycle["baselineState"] = "unchanged"
    elif status == "resolved":
        lifecycle["baselineState"] = "absent"
    elif status in {"false_positive", "accepted_risk"}:
        justification = notes or (
            "Reviewer marked this finding as a false positive."
            if status == "false_positive"
            else "Reviewer accepted the documented risk."
        )
        lifecycle["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": justification}
        ]
    return properties, lifecycle


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


def evaluate_adapter_runtime_readiness(
    readiness: object,
    tool_ids: list[str],
    configured: dict,
    *,
    now: float | None = None,
) -> dict:
    requested = sorted(set(tool_ids))
    result = {
        "allowed": False,
        "fresh": False,
        "age_seconds": None,
        "requested": requested,
        "unavailable": requested,
    }
    if not isinstance(readiness, dict):
        return result
    checked_at = readiness.get("checked_at")
    inventory = readiness.get("adapters")
    if not isinstance(checked_at, (int, float)) or not isinstance(inventory, list):
        return result
    current_time = time.time() if now is None else now
    age = current_time - float(checked_at)
    if age < -30 or age > MAX_RUNNER_READINESS_AGE_SECONDS:
        result["age_seconds"] = round(max(0.0, age), 1)
        return result
    by_tool: dict[str, dict] = {}
    duplicates: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict) or not isinstance(item.get("tool_id"), str):
            continue
        tool_id = item["tool_id"]
        if tool_id in by_tool:
            duplicates.add(tool_id)
        by_tool[tool_id] = item
    unavailable = []
    for tool_id in requested:
        item = by_tool.get(tool_id)
        adapter = configured.get(tool_id)
        expected_image = adapter.get("image") if isinstance(adapter, dict) else None
        if (
            tool_id in duplicates
            or item is None
            or item.get("state") != "ready"
            or not item.get("image_id")
            or item.get("image") != expected_image
        ):
            unavailable.append(tool_id)
    result.update({
        "allowed": not unavailable,
        "fresh": True,
        "age_seconds": round(max(0.0, age), 1),
        "unavailable": unavailable,
    })
    return result


def adapter_runtime_admission(tool_ids: list[str], configured: dict, *, enforce: bool = False) -> dict:
    raw = queue_client().get(RUNNER_READINESS)
    try:
        readiness = json.loads(raw) if raw else None
    except (json.JSONDecodeError, TypeError):
        readiness = None
    result = evaluate_adapter_runtime_readiness(readiness, tool_ids, configured)
    if enforce and not result["allowed"]:
        unavailable = ", ".join(result["unavailable"]) or "readiness inventory"
        raise HTTPException(
            status_code=503,
            detail=f"Adapter runtime is not ready for: {unavailable}; wait for runner inventory or install the pinned image",
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


DEPLOYMENT_SECURITY_SERVICES = {"api", "runner", "dashboard"}
DEPLOYMENT_SECURITY_FLAGS = (
    "read_only",
    "capabilities_dropped",
    "no_new_privileges",
    "non_root",
    "running",
)


def read_deployment_security_status(path: Path, *, now: datetime | None = None) -> dict:
    unavailable = {"available": False, "enforced": False, "services": []}
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024:
            return unavailable
        payload = json.loads(path.read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(str(payload["checked_at"]).replace("Z", "+00:00"))
        if checked_at.tzinfo is None:
            return unavailable
        services = payload.get("services")
        if not isinstance(services, list) or len(services) != len(DEPLOYMENT_SECURITY_SERVICES):
            return unavailable
        normalized_services = []
        names = set()
        for service in services:
            if not isinstance(service, dict) or service.get("service") not in DEPLOYMENT_SECURITY_SERVICES:
                return unavailable
            name = service["service"]
            if name in names or any(type(service.get(flag)) is not bool for flag in DEPLOYMENT_SECURITY_FLAGS):
                return unavailable
            restart_count = service.get("restart_count")
            if type(restart_count) is not int or restart_count < 0:
                return unavailable
            names.add(name)
            normalized_services.append({
                "service": name,
                **{flag: service[flag] for flag in DEPLOYMENT_SECURITY_FLAGS},
                "restart_count": restart_count,
            })
        if names != DEPLOYMENT_SECURITY_SERVICES:
            return unavailable
        current_time = now or datetime.now(timezone.utc)
        age = (current_time - checked_at.astimezone(timezone.utc)).total_seconds()
        if age < -60:
            return unavailable
        age_seconds = max(0, int(age))
        enforced = all(
            all(service[flag] for flag in DEPLOYMENT_SECURITY_FLAGS)
            for service in normalized_services
        )
        return {
            "available": True,
            "enforced": enforced,
            "checked_at": checked_at,
            "age_seconds": age_seconds,
            "fresh": age_seconds <= 600,
            "services": sorted(normalized_services, key=lambda item: item["service"]),
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return unavailable


@app.get("/deployment-security-status")
def deployment_security_status() -> dict:
    return read_deployment_security_status(DEPLOYMENT_SECURITY_STATUS_PATH)


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
        "deployment_security": deployment_security_status(),
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
    immutable_images = sum(
        1 for name in implemented_names
        if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", str(configured[name].get("image") or ""))
    )
    by_execution: dict[str, int] = {}
    for metadata in registry.values():
        mode = str(metadata.get("execution") or "unspecified")
        by_execution[mode] = by_execution.get(mode, 0) + 1
    non_adapter = [
        {"id": name, **metadata}
        for name, metadata in sorted(registry.items())
        if metadata.get("execution") not in eligible_modes
    ]
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                WITH counts AS (
                    SELECT tool_id,
                           count(*) FILTER (WHERE status = 'succeeded') AS succeeded,
                           count(*) FILTER (WHERE status = 'failed') AS failed
                    FROM runs
                    GROUP BY tool_id
                ), latest AS (
                    SELECT DISTINCT ON (tool_id)
                           tool_id, id, finished_at, evidence_manifest_sha256, evidence_sealed_at
                    FROM runs
                    WHERE status = 'succeeded'
                    ORDER BY tool_id, finished_at DESC NULLS LAST, created_at DESC
                )
                SELECT counts.tool_id, counts.succeeded, counts.failed,
                       latest.id, latest.finished_at,
                       latest.evidence_manifest_sha256, latest.evidence_sealed_at
                FROM counts
                LEFT JOIN latest USING (tool_id)
                """
            )
            run_history = {
                row[0]: {
                    "succeeded": int(row[1] or 0),
                    "failed": int(row[2] or 0),
                    "last_run_id": row[3],
                    "last_succeeded_at": row[4].isoformat() if row[4] else None,
                    "manifest_sha256": row[5],
                    "sealed_at": row[6],
                }
                for row in cursor.fetchall()
            }
    validation = []
    for name in implemented_names:
        history = run_history.get(name, {
            "succeeded": 0, "failed": 0, "last_run_id": None,
            "last_succeeded_at": None, "manifest_sha256": None, "sealed_at": None,
        })
        current_image = str(configured[name].get("image") or "")
        proven_image = None
        integrity_status = "unsealed"
        run_id = history["last_run_id"]
        if run_id:
            run_directory = EVIDENCE_ROOT / str(run_id)
            metadata_path = run_directory / "metadata.json"
            try:
                if metadata_path.is_symlink() or not metadata_path.is_file():
                    raise OSError("metadata is missing")
                if metadata_path.stat().st_size > MAX_EVIDENCE_BYTES:
                    raise OSError("metadata exceeds read limit")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                proven_image = str(metadata.get("image") or "")
                integrity_status = verify_evidence_integrity(
                    run_id, run_directory, history["manifest_sha256"], history["sealed_at"]
                )["status"]
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
                integrity_status = "failed"
        image_matches = bool(proven_image and proven_image == current_image)
        validated = image_matches and integrity_status == "verified"
        requires_external_approval = bool(configured[name].get("uses_third_party_services"))
        if validated:
            validation_state = "proven"
            validation_note = "Current pinned image has a successful run with verified sealed evidence."
        elif requires_external_approval and not history["succeeded"]:
            validation_state = "external-approval-required"
            validation_note = (
                "Runtime proof requires an explicitly authorized domain and separate opt-in "
                "to third-party providers; local fixtures cannot prove provider connectivity."
            )
        elif not run_id:
            validation_state = "not-run"
            validation_note = "No successful runtime proof has been recorded for this adapter."
        elif not image_matches:
            validation_state = "image-mismatch"
            validation_note = "The latest successful proof used a different image digest."
        else:
            validation_state = "evidence-unverified"
            validation_note = "The latest successful run does not have verified sealed evidence."
        validation.append({
            "id": name,
            "input": str(configured[name].get("input") or "target"),
            "profile": str(configured[name].get("profile") or "unknown"),
            "validated": validated,
            "validation_state": validation_state,
            "validation_note": validation_note,
            "requires_external_approval": requires_external_approval,
            "succeeded": history["succeeded"],
            "failed": history["failed"],
            "last_run_id": run_id,
            "last_succeeded_at": history["last_succeeded_at"],
            "current_image": current_image,
            "proven_image": proven_image,
            "image_matches": image_matches,
            "integrity_status": integrity_status,
        })
    validated_count = sum(1 for item in validation if item["validated"])
    return {
        "totals": {
            "catalogued": len(registry),
            "adapter_eligible": eligible_count,
            "implemented": implemented_count,
            "immutable_images": immutable_images,
            "floating_images": implemented_count - immutable_images,
            "pending": len(pending_names),
            "non_adapter": len(non_adapter),
            "coverage_percent": round((implemented_count / eligible_count) * 100, 1) if eligible_count else 0,
            "validated": validated_count,
            "validation_pending": implemented_count - validated_count,
            "validation_percent": round((validated_count / implemented_count) * 100, 1) if implemented_count else 0,
        },
        "by_profile": dict(sorted(by_profile.items())),
        "by_input": dict(sorted(by_input.items())),
        "by_execution": dict(sorted(by_execution.items())),
        "by_category": dict(sorted(by_category.items())),
        "pending": [
            {"id": name, **eligible[name]}
            for name in pending_names
        ],
        "validation": validation,
        "non_adapter": non_adapter,
    }


@app.get("/local-validation-status")
def local_validation_status() -> dict:
    if not VALIDATION_STATUS_PATH.is_file() or VALIDATION_STATUS_PATH.is_symlink():
        return {"available": False, "detail": "No local validation suite result is available"}
    if VALIDATION_STATUS_PATH.stat().st_size > 16 * 1024:
        raise HTTPException(status_code=413, detail="Local validation status exceeds the read limit")
    try:
        payload = json.loads(VALIDATION_STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Local validation status is unreadable") from exc
    required = {"started_at", "finished_at", "mode", "status"}
    if (
        not required.issubset(payload)
        or payload["mode"] not in {"quick", "full"}
        or payload["status"] not in {"running", "passed", "failed"}
        or (payload["status"] == "running") != (payload["finished_at"] is None)
    ):
        raise HTTPException(status_code=503, detail="Local validation status has an invalid schema")
    try:
        reference_at = datetime.fromisoformat(
            str(payload["finished_at"] or payload["started_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Local validation timestamp is invalid") from exc
    age_seconds = max(0, int((datetime.now(timezone.utc) - reference_at).total_seconds()))
    return {
        "available": True,
        "started_at": payload["started_at"],
        "finished_at": payload["finished_at"],
        "mode": payload["mode"],
        "status": payload["status"],
        "age_seconds": age_seconds,
    }


@app.get("/local-source-validation-status")
def local_source_validation_status() -> dict:
    path = SOURCE_VALIDATION_STATUS_PATH
    if not path.is_file() or path.is_symlink():
        return {"available": False, "detail": "No local source validation result is available"}
    if path.stat().st_size > 16 * 1024:
        raise HTTPException(status_code=413, detail="Local source validation status exceeds the read limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Local source validation status is unreadable") from exc
    required = {"started_at", "finished_at", "mode", "status", "completed_tools", "total_observations"}
    if (
        not required.issubset(payload)
        or payload["mode"] not in {"quick", "full"}
        or payload["status"] not in {"running", "passed", "failed"}
        or (payload["status"] == "running") != (payload["finished_at"] is None)
        or not isinstance(payload["completed_tools"], int)
        or not isinstance(payload["total_observations"], int)
        or payload["completed_tools"] < 0
        or payload["total_observations"] < 0
    ):
        raise HTTPException(status_code=503, detail="Local source validation status has an invalid schema")
    try:
        reference_at = datetime.fromisoformat(
            str(payload["finished_at"] or payload["started_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Local source validation timestamp is invalid") from exc
    return {
        "available": True,
        **{key: payload[key] for key in required},
        "age_seconds": max(0, int((datetime.now(timezone.utc) - reference_at).total_seconds())),
    }


@app.get("/image-audit-status")
def image_audit_status() -> dict:
    reports = [
        path for path in IMAGE_AUDIT_ROOT.glob("*.trivy.json")
        if path.is_file() and not path.is_symlink()
    ]
    if not reports:
        return {"available": False, "detail": "No container image audit is available"}
    latest = max(reports, key=lambda path: path.stat().st_mtime)
    size = latest.stat().st_size
    if size > 32 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Latest image audit exceeds the read limit")
    try:
        report = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Latest image audit is unreadable") from exc
    vulnerabilities = [
        vulnerability
        for result in report.get("Results", [])
        if isinstance(result, dict)
        for vulnerability in (result.get("Vulnerabilities") or [])
        if isinstance(vulnerability, dict)
    ]
    severity_counts = {
        severity.lower(): sum(
            1 for item in vulnerabilities if item.get("Severity") == severity
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    }
    fixable_counts = {
        severity.lower(): sum(
            1
            for item in vulnerabilities
            if item.get("Severity") == severity and item.get("FixedVersion")
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    }
    prefix = latest.name.removesuffix(".trivy.json")
    sbom = IMAGE_AUDIT_ROOT / f"{prefix}.sbom.json"
    checksums = IMAGE_AUDIT_ROOT / f"{prefix}.sha256"
    checksum_verified = False
    if (
        sbom.is_file()
        and not sbom.is_symlink()
        and sbom.stat().st_size <= 64 * 1024 * 1024
        and checksums.is_file()
        and not checksums.is_symlink()
        and checksums.stat().st_size <= 64 * 1024
    ):
        try:
            expected = {}
            for line in checksums.read_text(encoding="utf-8").splitlines():
                match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line)
                if match:
                    name = PurePosixPath(match.group(2)).name
                    if name in {latest.name, sbom.name}:
                        expected[name] = match.group(1).lower()
            checksum_verified = all(
                expected.get(path.name) == hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (latest, sbom)
            )
        except (OSError, UnicodeDecodeError):
            checksum_verified = False
    metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
    audited_at = datetime.fromtimestamp(latest.stat().st_mtime, timezone.utc)
    age_seconds = max(0, int((datetime.now(timezone.utc) - audited_at).total_seconds()))
    return {
        "available": True,
        "audited_at": audited_at,
        "age_seconds": age_seconds,
        "fresh": age_seconds <= MAX_IMAGE_AUDIT_AGE_HOURS * 3600,
        "max_age_hours": MAX_IMAGE_AUDIT_AGE_HOURS,
        "artifact_name": str(report.get("ArtifactName") or "local image"),
        "artifact_type": str(report.get("ArtifactType") or "container_image"),
        "image_id": str(metadata.get("ImageID") or ""),
        "report": {"filename": latest.name, "size_bytes": size},
        "sbom": {"available": sbom.is_file(), "filename": sbom.name if sbom.is_file() else None},
        "checksums": {
            "available": checksums.is_file(),
            "filename": checksums.name if checksums.is_file() else None,
            "verified": checksum_verified,
        },
        "severity_counts": severity_counts,
        "fixable_counts": fixable_counts,
        "total_vulnerabilities": len(vulnerabilities),
    }


@app.get("/image-audit-history")
def image_audit_history(limit: int = 10) -> dict:
    if not 1 <= limit <= 10:
        raise HTTPException(status_code=422, detail="Image audit history limit must be between 1 and 10")
    reports = sorted(
        (
            path for path in IMAGE_AUDIT_ROOT.glob("*.trivy.json")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:limit]
    audits = []
    for report_path in reports:
        size = report_path.stat().st_size
        if size > 32 * 1024 * 1024:
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        vulnerabilities = [
            item
            for result in report.get("Results", [])
            if isinstance(result, dict)
            for item in (result.get("Vulnerabilities") or [])
            if isinstance(item, dict)
        ]
        prefix = report_path.name.removesuffix(".trivy.json")
        sbom = IMAGE_AUDIT_ROOT / f"{prefix}.sbom.json"
        checksums = IMAGE_AUDIT_ROOT / f"{prefix}.sha256"
        integrity_verified = False
        if (
            sbom.is_file()
            and not sbom.is_symlink()
            and sbom.stat().st_size <= 64 * 1024 * 1024
            and checksums.is_file()
            and not checksums.is_symlink()
            and checksums.stat().st_size <= 64 * 1024
        ):
            try:
                expected = {
                    PurePosixPath(match.group(2)).name: match.group(1).lower()
                    for line in checksums.read_text(encoding="utf-8").splitlines()
                    if (match := re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line))
                }
                integrity_verified = all(
                    expected.get(path.name) == hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (report_path, sbom)
                )
            except (OSError, UnicodeDecodeError):
                integrity_verified = False
        audited_at = datetime.fromtimestamp(report_path.stat().st_mtime, timezone.utc)
        age_seconds = max(0, int((datetime.now(timezone.utc) - audited_at).total_seconds()))
        audits.append({
            "audited_at": audited_at,
            "age_seconds": age_seconds,
            "fresh": age_seconds <= MAX_IMAGE_AUDIT_AGE_HOURS * 3600,
            "artifact_name": str(report.get("ArtifactName") or "local image"),
            "image_id": str((report.get("Metadata") or {}).get("ImageID") or "")
            if isinstance(report.get("Metadata"), dict) else "",
            "report_filename": report_path.name,
            "size_bytes": size,
            "critical": sum(1 for item in vulnerabilities if item.get("Severity") == "CRITICAL"),
            "high": sum(1 for item in vulnerabilities if item.get("Severity") == "HIGH"),
            "fixable_high": sum(
                1 for item in vulnerabilities
                if item.get("Severity") == "HIGH" and item.get("FixedVersion")
            ),
            "integrity_verified": integrity_verified,
        })
    return {"audits": audits, "limit": limit}


@app.get("/image-audit-artifacts/{artifact_kind}")
def download_image_audit_artifact(artifact_kind: str) -> FileResponse:
    artifact_suffixes = {
        "report": (".trivy.json", "application/json"),
        "sbom": (".sbom.json", "application/vnd.cyclonedx+json"),
        "checksums": (".sha256", "text/plain"),
    }
    if artifact_kind not in artifact_suffixes:
        raise HTTPException(status_code=404, detail="Unknown image audit artifact")
    audit_status = image_audit_status()
    if not audit_status.get("available"):
        raise HTTPException(status_code=404, detail="No container image audit is available")
    if not audit_status.get("checksums", {}).get("verified"):
        raise HTTPException(status_code=409, detail="Image audit artifact integrity is unverified")
    reports = [
        path for path in IMAGE_AUDIT_ROOT.glob("*.trivy.json")
        if path.is_file() and not path.is_symlink()
    ]
    if not reports:
        raise HTTPException(status_code=404, detail="No container image audit is available")
    latest = max(reports, key=lambda path: path.stat().st_mtime)
    suffix, media_type = artifact_suffixes[artifact_kind]
    prefix = latest.name.removesuffix(".trivy.json")
    artifact = (IMAGE_AUDIT_ROOT / f"{prefix}{suffix}").resolve()
    audit_root = IMAGE_AUDIT_ROOT.resolve()
    if artifact.parent != audit_root or not artifact.is_file():
        raise HTTPException(status_code=404, detail="Image audit artifact is not available")
    if artifact.stat().st_size > 64 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image audit artifact exceeds the download limit")
    return FileResponse(artifact, media_type=media_type, filename=artifact.name)


@app.get("/backup-status")
def backup_status() -> dict:
    database_backups = sorted(
        (
            path for path in BACKUP_ROOT.glob("postgres-*.sql.gz")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not database_backups:
        return {"available": False, "detail": "No database backup is available"}
    database_backup = database_backups[0]
    match = re.fullmatch(r"postgres-(\d{8}T\d{6}Z)\.sql\.gz", database_backup.name)
    if not match:
        raise HTTPException(status_code=503, detail="Latest database backup name is invalid")
    timestamp = match.group(1)
    config_backup = BACKUP_ROOT / f"config-{timestamp}.tar.gz"
    paired = config_backup.is_file() and not config_backup.is_symlink()
    database_valid = False
    config_valid = False
    if database_backup.stat().st_size <= 512 * 1024 * 1024:
        try:
            expanded = 0
            with gzip.open(database_backup, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    expanded += len(chunk)
                    if expanded > 1024 * 1024 * 1024:
                        raise ValueError("Database backup expands beyond the validation limit")
            database_valid = expanded > 0
        except (OSError, EOFError, ValueError):
            database_valid = False
    if paired and config_backup.stat().st_size <= 512 * 1024 * 1024:
        try:
            with tarfile.open(config_backup, "r:gz") as archive:
                members = archive.getmembers()
                config_valid = 0 < len(members) <= 10_000 and all(
                    not PurePosixPath(member.name).is_absolute()
                    and ".." not in PurePosixPath(member.name).parts
                    for member in members
                )
        except (OSError, EOFError, tarfile.TarError):
            config_valid = False
    created_at = datetime.fromtimestamp(database_backup.stat().st_mtime, timezone.utc)
    age_seconds = max(0, int((datetime.now(timezone.utc) - created_at).total_seconds()))
    restore_validation = {"available": False, "status": "not-run", "matches_latest": False}
    try:
        if BACKUP_RESTORE_STATUS_PATH.is_symlink() or not BACKUP_RESTORE_STATUS_PATH.is_file():
            raise OSError("restore status is unavailable")
        if BACKUP_RESTORE_STATUS_PATH.stat().st_size > 64 * 1024:
            raise OSError("restore status exceeds read limit")
        restore_payload = json.loads(BACKUP_RESTORE_STATUS_PATH.read_text(encoding="utf-8"))
        restore_validation = {
            "available": True,
            "status": str(restore_payload.get("status") or "unknown"),
            "backup": restore_payload.get("backup"),
            "finished_at": restore_payload.get("finished_at"),
            "row_counts": restore_payload.get("row_counts") or [],
            "matches_latest": restore_payload.get("backup") == database_backup.name,
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {
        "available": True,
        "timestamp": timestamp,
        "created_at": created_at,
        "age_seconds": age_seconds,
        "fresh": age_seconds <= MAX_BACKUP_AGE_HOURS * 3600,
        "max_age_hours": MAX_BACKUP_AGE_HOURS,
        "paired": paired,
        "verified": paired and database_valid and config_valid,
        "database": {
            "filename": database_backup.name,
            "size_bytes": database_backup.stat().st_size,
            "valid": database_valid,
        },
        "configuration": {
            "filename": config_backup.name if paired else None,
            "size_bytes": config_backup.stat().st_size if paired else None,
            "valid": config_valid,
        },
        "restore_validation": restore_validation,
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


@app.get("/projects/{project_id}/workflow-templates")
def list_workflow_templates(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, name, tool_ids, created_by, created_at
                FROM workflow_templates WHERE project_id = %s ORDER BY created_at DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
    return {
        "templates": [
            {"id": row[0], "name": row[1], "tool_ids": row[2], "created_by": row[3], "created_at": row[4]}
            for row in rows
        ]
    }


@app.post("/projects/{project_id}/workflow-templates", status_code=201)
def create_workflow_template(project_id: UUID, payload: WorkflowTemplateCreate) -> dict:
    validate_workflow_tool_ids(payload.tool_ids)
    template_id = uuid4()
    try:
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
                if cursor.fetchone() is None:
                    raise HTTPException(status_code=404, detail="Project not found")
                cursor.execute(
                    """
                    INSERT INTO workflow_templates (id, project_id, name, tool_ids, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (template_id, project_id, payload.name.strip(), Jsonb(payload.tool_ids), payload.created_by),
                )
                record_audit(
                    cursor, project_id, "workflow_template.created", payload.created_by,
                    "workflow_template", template_id, {"name": payload.name.strip(), "tools": payload.tool_ids},
                )
    except psycopg.errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="A workflow template with this name already exists") from exc
    return {"id": template_id, "project_id": project_id, **payload.model_dump()}


@app.delete("/workflow-templates/{template_id}")
def delete_workflow_template(template_id: UUID, payload: WorkflowTemplateDelete) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM workflow_templates WHERE id = %s RETURNING project_id, name, tool_ids",
                (template_id,),
            )
            deleted = cursor.fetchone()
            if deleted is None:
                raise HTTPException(status_code=404, detail="Workflow template not found")
            record_audit(
                cursor, deleted[0], "workflow_template.deleted", payload.requested_by,
                "workflow_template", template_id, {"name": deleted[1], "tools": deleted[2]},
            )
    return {"id": template_id, "deleted": True}


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
    _, _, dns_resolver = normalize_target_policy(payload)

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
                     max_run_seconds, testing_window_start_minute_utc,
                     testing_window_end_minute_utc, allow_state_changing,
                     allow_third_party_services, authorization_reference,
                     authorization_confirmed)
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s, %s, %s, TRUE)
                """,
                (
                    target_id,
                    project_id,
                    str(payload.base_url),
                    Jsonb(payload.allowed_hosts),
                    Jsonb(payload.excluded_paths),
                    dns_resolver,
                    payload.max_run_seconds,
                    payload.testing_window_start_minute_utc,
                    payload.testing_window_end_minute_utc,
                    payload.allow_state_changing,
                    payload.allow_third_party_services,
                    payload.authorization_reference,
                ),
            )
            record_audit(
                cursor, project_id, "target.authorized", "system", "target", target_id,
                {
                    "base_url": str(payload.base_url),
                    "dns_resolver": dns_resolver,
                    "max_run_seconds": payload.max_run_seconds,
                    "testing_window_start_minute_utc": payload.testing_window_start_minute_utc,
                    "testing_window_end_minute_utc": payload.testing_window_end_minute_utc,
                    "allow_state_changing": payload.allow_state_changing,
                    "allow_third_party_services": payload.allow_third_party_services,
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
                       max_run_seconds, testing_window_start_minute_utc,
                       testing_window_end_minute_utc, allow_state_changing,
                       allow_third_party_services, authorization_reference,
                       authorization_confirmed, created_at
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
                "max_run_seconds": row[5],
                "testing_window_start_minute_utc": row[6],
                "testing_window_end_minute_utc": row[7],
                "allow_state_changing": row[8],
                "allow_third_party_services": row[9],
                "authorization_reference": row[10],
                "authorization_confirmed": row[11], "created_at": row[12],
            }
            for row in rows
        ]
    }


@app.put("/projects/{project_id}/targets/{target_id}")
def update_target(project_id: UUID, target_id: UUID, payload: TargetUpdate) -> dict:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Explicit target authorization confirmation is required")
    base_host, allowed_hosts, dns_resolver = normalize_target_policy(payload)
    updated_base_url = str(payload.base_url)
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT base_url, allowed_hosts, excluded_paths, dns_resolver,
                       max_run_seconds, testing_window_start_minute_utc,
                       testing_window_end_minute_utc, allow_state_changing,
                       allow_third_party_services, authorization_reference
                FROM targets
                WHERE id = %s AND project_id = %s
                FOR UPDATE
                """,
                (target_id, project_id),
            )
            previous = cursor.fetchone()
            if previous is None:
                raise HTTPException(status_code=404, detail="Target not found in project")
            if updated_base_url != previous[0]:
                raise HTTPException(
                    status_code=409,
                    detail="Target base URL is immutable; create a new target for a different base URL",
                )
            cursor.execute(
                """
                SELECT COUNT(*) FROM runs
                WHERE target_id = %s
                  AND status IN ('queued', 'running', 'cancelling')
                """,
                (target_id,),
            )
            if cursor.fetchone()[0]:
                raise HTTPException(
                    status_code=409,
                    detail="Target policy cannot change while it has active or queued runs",
                )
            cursor.execute(
                "SELECT name, login_url FROM credential_profiles WHERE target_id = %s",
                (target_id,),
            )
            for profile_name, login_url in cursor.fetchall():
                parsed_login = urlsplit(login_url)
                login_host = (parsed_login.hostname or "").lower().rstrip(".")
                if (
                    login_host != base_host
                    or login_host not in allowed_hosts
                    or target_path_is_excluded(parsed_login.path or "/", payload.excluded_paths)
                ):
                    raise HTTPException(
                        status_code=409,
                        detail=f"Updated scope would invalidate stored credential profile: {profile_name}",
                    )
            cursor.execute(
                """
                UPDATE targets
                SET allowed_hosts = %s::jsonb,
                    excluded_paths = %s::jsonb,
                    dns_resolver = %s,
                    max_run_seconds = %s,
                    testing_window_start_minute_utc = %s,
                    testing_window_end_minute_utc = %s,
                    allow_state_changing = %s,
                    allow_third_party_services = %s,
                    authorization_reference = %s,
                    authorization_confirmed = TRUE
                WHERE id = %s AND project_id = %s
                """,
                (
                    Jsonb(payload.allowed_hosts),
                    Jsonb(payload.excluded_paths),
                    dns_resolver,
                    payload.max_run_seconds,
                    payload.testing_window_start_minute_utc,
                    payload.testing_window_end_minute_utc,
                    payload.allow_state_changing,
                    payload.allow_third_party_services,
                    payload.authorization_reference,
                    target_id,
                    project_id,
                ),
            )
            record_audit(
                cursor, project_id, "target.policy_updated", payload.requested_by,
                "target", target_id,
                {
                    "previous": {
                        "allowed_hosts": previous[1],
                        "excluded_paths": previous[2],
                        "dns_resolver": previous[3],
                        "max_run_seconds": previous[4],
                        "testing_window_start_minute_utc": previous[5],
                        "testing_window_end_minute_utc": previous[6],
                        "allow_state_changing": previous[7],
                        "allow_third_party_services": previous[8],
                        "authorization_reference": previous[9],
                    },
                    "current": {
                        "allowed_hosts": payload.allowed_hosts,
                        "excluded_paths": payload.excluded_paths,
                        "dns_resolver": dns_resolver,
                        "max_run_seconds": payload.max_run_seconds,
                        "testing_window_start_minute_utc": payload.testing_window_start_minute_utc,
                        "testing_window_end_minute_utc": payload.testing_window_end_minute_utc,
                        "allow_state_changing": payload.allow_state_changing,
                        "allow_third_party_services": payload.allow_third_party_services,
                        "authorization_reference": payload.authorization_reference,
                    },
                },
            )
    return {
        "id": target_id,
        "project_id": project_id,
        **payload.model_dump(mode="json", exclude={"dns_resolver", "requested_by"}),
        "dns_resolver": dns_resolver,
        "updated_by": payload.requested_by,
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
    adapter_runtime_admission([payload.tool_id], adapters, enforce=True)
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
                    """
                    SELECT authorization_confirmed, testing_window_start_minute_utc,
                           testing_window_end_minute_utc, allow_state_changing,
                           allow_third_party_services
                    FROM targets WHERE id = %s AND project_id = %s
                    """,
                    (payload.target_id, project_id),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Target not found in project")
                if not target[0]:
                    raise HTTPException(status_code=422, detail="Target authorization is not confirmed")
                require_open_testing_window(target[1], target[2])
                require_state_changing_permission(payload.profile, target[3])
                require_third_party_service_permission(
                    bool(adapter.get("uses_third_party_services", False)),
                    target[4],
                )
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
    choices = sum(value is not None for value in (payload.plan_id, payload.tool_ids, payload.template_id))
    if choices != 1:
        raise HTTPException(status_code=422, detail="Select exactly one preset plan, saved template, or custom tool sequence")
    template_name = None
    if payload.template_id is not None:
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT name, tool_ids FROM workflow_templates WHERE id = %s AND project_id = %s",
                    (payload.template_id, project_id),
                )
                template = cursor.fetchone()
                if template is None:
                    raise HTTPException(status_code=404, detail="Workflow template not found in project")
                template_name, template_tools = template
        tool_ids = list(template_tools)
    else:
        tool_ids = list(RUN_PLANS[payload.plan_id]) if payload.plan_id else list(payload.tool_ids or [])
    adapters = validate_workflow_tool_ids(tool_ids)
    adapter_runtime_admission(tool_ids, adapters, enforce=True)
    plan_id = (
        payload.plan_id
        or (f"template-{payload.template_id}" if payload.template_id else None)
        or f"custom-{hashlib.sha256(json.dumps(tool_ids).encode()).hexdigest()[:12]}"
    )
    if payload.credential_profile_id is not None and "playwright" not in tool_ids:
        raise HTTPException(status_code=422, detail="Selected workflow does not contain a Playwright step")
    queue_admission(requested_slots=len(tool_ids), enforce=True)
    batch_id = uuid4()
    run_ids = [uuid4() for _ in tool_ids]
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT authorization_confirmed, testing_window_start_minute_utc,
                       testing_window_end_minute_utc, allow_state_changing,
                       allow_third_party_services
                FROM targets WHERE id = %s AND project_id = %s
                """,
                (payload.target_id, project_id),
            )
            target = cursor.fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found in project")
            if not target[0]:
                raise HTTPException(status_code=422, detail="Target authorization is not confirmed")
            require_open_testing_window(target[1], target[2])
            for tool_id in tool_ids:
                require_state_changing_permission(
                    adapters[tool_id].get("profile", ""),
                    target[3],
                    workflow=True,
                )
                require_third_party_service_permission(
                    bool(adapters[tool_id].get("uses_third_party_services", False)),
                    target[4],
                    workflow=True,
                )
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
                    (id, project_id, target_id, credential_profile_id, template_id, plan_id, requested_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    batch_id, project_id, payload.target_id, payload.credential_profile_id,
                    payload.template_id, plan_id, payload.requested_by,
                ),
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
                    "target_id": str(payload.target_id), "plan_id": plan_id,
                    "plan_type": "preset" if payload.plan_id else "template" if payload.template_id else "custom",
                    "template_id": str(payload.template_id) if payload.template_id else None,
                    "template_name": template_name, "tools": tool_ids,
                    "credential_profile_id": str(payload.credential_profile_id) if payload.credential_profile_id else None,
                    "credential_role": credential_role,
                },
            )

    queue_client().rpush(RUN_QUEUE, str(run_ids[0]))
    return {
        "id": batch_id,
        "status": "queued",
        "plan_id": plan_id,
        "template_id": payload.template_id,
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
                SELECT id, target_id, plan_id, requested_by, created_at, credential_profile_id, template_id
                FROM run_batches WHERE project_id = %s ORDER BY created_at DESC
                """,
                (project_id,),
            )
            batches = []
            for row in cursor.fetchall():
                cursor.execute(
                    """
                    SELECT id, project_id, target_id, tool_id, profile, status,
                           requested_by, error_message, created_at, started_at, finished_at,
                           retest_of_observation, source_artifact_id, credential_profile_id
                    FROM runs WHERE batch_id = %s ORDER BY batch_step, created_at
                    """,
                    (row[0],),
                )
                runs = [run_row(run) for run in cursor.fetchall()]
                statuses = [run["status"] for run in runs]
                batches.append(
                    {
                        "id": row[0], "target_id": row[1], "plan_id": row[2],
                        "requested_by": row[3], "created_at": row[4], "credential_profile_id": row[5],
                        "template_id": row[6],
                        "status": derive_batch_status(statuses),
                        "status_counts": {status: statuses.count(status) for status in sorted(set(statuses))},
                        "runs": runs,
                    }
                )
    return {"batches": batches}


@app.get("/batches/{batch_id}")
def get_batch(batch_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, project_id, target_id, plan_id, requested_by, created_at, credential_profile_id, template_id FROM run_batches WHERE id = %s",
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
        "credential_profile_id": batch[6], "template_id": batch[7],
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


@app.get("/runs/{run_id}/retest-result")
def get_retest_result(run_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT project_id, tool_id, status, retest_of_observation, finished_at
                FROM runs WHERE id = %s
                """,
                (run_id,),
            )
            run = cursor.fetchone()
            if run is None:
                raise HTTPException(status_code=404, detail="Run not found")
            if run[3] is None:
                raise HTTPException(status_code=422, detail="Run is not a finding retest")
            cursor.execute(
                """
                SELECT id, title, severity, asset, fingerprint, review_status
                FROM observations WHERE id = %s
                """,
                (run[3],),
            )
            original = cursor.fetchone()
            if original is None:
                raise HTTPException(status_code=409, detail="Original finding is unavailable")
            cursor.execute(
                """
                SELECT id, title, severity, asset, created_at
                FROM observations
                WHERE run_id = %s AND fingerprint = %s
                ORDER BY created_at
                """,
                (run_id, original[4]),
            )
            matches = cursor.fetchall()

    if run[2] in {"queued", "running", "cancelling"}:
        comparison = "pending"
        conclusion = "Retest is still in progress."
    elif run[2] in {"failed", "cancelled"}:
        comparison = "inconclusive"
        conclusion = "Retest did not complete successfully, so no comparison can be made."
    elif matches:
        comparison = "persisting"
        conclusion = "The same normalized finding fingerprint was observed again."
    else:
        comparison = "not_observed"
        conclusion = "The original fingerprint was not observed in this successful retest."

    return {
        "run_id": run_id,
        "project_id": run[0],
        "tool_id": run[1],
        "run_status": run[2],
        "finished_at": run[4],
        "comparison": comparison,
        "conclusion": conclusion,
        "original": {
            "id": original[0],
            "title": original[1],
            "severity": original[2],
            "asset": original[3],
            "fingerprint": original[4],
            "review_status": original[5],
        },
        "matches": [
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "asset": row[3],
                "created_at": row[4],
            }
            for row in matches
        ],
        "disclaimer": (
            "A not_observed result is evidence from this bounded retest only; it does not prove the issue is fixed. "
            "Review scope, tool coverage, and evidence before marking the finding resolved."
        ),
    }


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


@app.get("/runs/{run_id}/evidence-bundle")
def download_run_evidence_bundle(run_id: UUID) -> Response:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT project_id, tool_id, profile, status, requested_by, created_at,
                       started_at, finished_at, error_message,
                       evidence_manifest_sha256, evidence_sealed_at
                FROM runs WHERE id = %s
                """,
                (run_id,),
            )
            run = cursor.fetchone()
            if run is None:
                raise HTTPException(status_code=404, detail="Run not found")
            if run[3] not in {"succeeded", "failed", "cancelled"}:
                raise HTTPException(status_code=409, detail="Evidence can be exported only after the run is terminal")

            run_directory = EVIDENCE_ROOT / str(run_id)
            integrity = verify_evidence_integrity(run_id, run_directory, run[9], run[10])
            if integrity["status"] != "verified":
                raise HTTPException(status_code=409, detail="Legacy unsealed evidence cannot be exported")

            cursor.execute(
                """
                SELECT id, observation_type, title, severity, asset, details, fingerprint,
                       created_at, review_status, review_notes, reviewed_by, reviewed_at
                FROM observations WHERE run_id = %s ORDER BY created_at, id
                """,
                (run_id,),
            )
            observations = [
                {
                    "id": row[0], "type": row[1], "title": row[2], "severity": row[3],
                    "asset": row[4], "details": sanitize_evidence(row[5]),
                    "fingerprint": row[6], "created_at": row[7],
                    "review_status": row[8], "review_notes": row[9],
                    "reviewed_by": row[10], "reviewed_at": row[11],
                }
                for row in cursor.fetchall()
            ]

            payloads = {
                "run.json": {
                    "run_id": run_id, "project_id": run[0], "tool_id": run[1],
                    "profile": run[2], "status": run[3], "requested_by": run[4],
                    "created_at": run[5], "started_at": run[6], "finished_at": run[7],
                    "error_message": run[8],
                },
                "metadata.json": read_json_file(run_directory / "metadata.json"),
                "events.json": read_jsonl_file(run_directory / "events.jsonl"),
                "output.json": read_jsonl_file(run_directory / "output.jsonl"),
                "observations.json": observations,
                "source-integrity.json": {
                    "status": integrity["status"],
                    "sealed_at": integrity["sealed_at"],
                    "sealed_files": integrity["files"],
                    "manifest_sha256": run[9],
                },
            }
            encoded_payloads = {
                name: json.dumps(value, indent=2, sort_keys=True, default=str).encode("utf-8") + b"\n"
                for name, value in payloads.items()
            }
            if sum(len(content) for content in encoded_payloads.values()) > MAX_RUN_EVIDENCE_BYTES:
                raise HTTPException(status_code=413, detail="Sanitized evidence bundle exceeds the per-run export limit")
            bundle_manifest = {
                "version": 1,
                "algorithm": "sha256",
                "run_id": str(run_id),
                "files": [
                    {"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    for name, content in encoded_payloads.items()
                ],
                "sanitization": "API redaction and display limits applied; raw scanner files are not included",
            }
            encoded_payloads["bundle-manifest.json"] = (
                json.dumps(bundle_manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            )

            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
                for name, content in encoded_payloads.items():
                    member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    member.compress_type = zipfile.ZIP_DEFLATED
                    member.external_attr = 0o600 << 16
                    bundle.writestr(member, content)

            record_audit(
                cursor, run[0], "run.evidence_exported", "control-plane-operator", "run", run_id,
                {"format": "sanitized-zip", "files": len(encoded_payloads)},
            )

    return Response(
        content=archive.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="security-platform-{run_id}-evidence.zip"'},
    )


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
            cursor.execute(
                """
                SELECT r.status, cp.role_name
                FROM runs r
                LEFT JOIN credential_profiles cp ON cp.id = r.credential_profile_id
                WHERE r.id = %s
                """,
                (run_id,),
            )
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
        "authenticated_role": run[1],
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
                    SELECT o.id, o.run_id, r.tool_id, cp.role_name AS credential_role,
                           o.observation_type, o.title, o.severity,
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
                    LEFT JOIN credential_profiles cp ON cp.id = r.credential_profile_id
                    WHERE r.project_id = %s
                )
                SELECT id, run_id, tool_id, credential_role, observation_type, title, severity, asset, details,
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
                "id": row[0], "run_id": row[1], "tool_id": row[2],
                "credential_role": row[3], "type": row[4],
                "title": row[5], "severity": row[6], "asset": row[7],
                "details": sanitize_evidence(row[8]), "fingerprint": row[9],
                "review_status": row[10], "review_notes": row[11],
                "reviewed_by": row[12], "reviewed_at": row[13],
                "occurrence_count": row[14], "first_seen": row[15], "last_seen": row[16],
            }
            for row in rows
        ],
    }


@app.get("/projects/{project_id}/report.sarif")
def get_project_sarif_report(project_id: UUID, include_info: bool = False) -> Response:
    finding_data = get_project_findings(project_id)
    findings = finding_data["findings"]
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]

    rules: dict[str, dict] = {}
    results: list[dict] = []
    level_by_severity = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    for finding in reported:
        review_properties, review_lifecycle = sarif_review_metadata(finding)
        raw_rule_id = f"security-platform/{finding['tool_id']}/{finding['type']}"
        rule_id = re.sub(r"[^A-Za-z0-9._/-]+", "-", raw_rule_id).strip("-")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": re.sub(r"[^A-Za-z0-9_]+", "_", str(finding["type"])).strip("_") or "finding",
                "shortDescription": {"text": str(finding["title"])},
                "properties": {
                    "toolId": str(finding["tool_id"]),
                    "observationType": str(finding["type"]),
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": level_by_severity.get(str(finding["severity"]), "warning"),
                "message": {"text": str(finding["title"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding["asset"] or "unknown")}
                        }
                    }
                ],
                "partialFingerprints": {
                    "securityPlatformFingerprint": str(finding["fingerprint"])
                },
                "properties": {
                    "severity": str(finding["severity"]),
                    "occurrenceCount": int(finding["occurrence_count"]),
                    "toolId": str(finding["tool_id"]),
                    "runId": str(finding["run_id"]),
                    "authenticatedRole": finding.get("credential_role"),
                    "firstSeen": str(finding["first_seen"]),
                    "lastSeen": str(finding["last_seen"]),
                    "details": finding["details"],
                    **review_properties,
                },
                **review_lifecycle,
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Security Testing Platform",
                        "semanticVersion": app.version,
                        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return Response(
        content=json.dumps(sarif, ensure_ascii=False, separators=(",", ":"), default=str),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="security-platform-{project_id}.sarif"'
        },
    )


def build_defectdojo_report(findings: list[dict], include_info: bool = False) -> dict:
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]
    severity_names = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    exported = []
    for finding in reported:
        review_status = str(finding.get("review_status") or "new")
        asset = str(finding.get("asset") or "")
        details = json.dumps(
            sanitize_evidence(finding.get("details")),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        item = {
            "title": (str(finding.get("title") or "Security observation")[:511]),
            "description": "\n".join([
                f"Source tool: {finding.get('tool_id') or 'unknown'}",
                f"Authenticated role: {finding.get('credential_role') or 'anonymous'}",
                f"Observation type: {finding.get('type') or 'unknown'}",
                f"Asset: {asset or 'unknown'}",
                f"Occurrences: {int(finding.get('occurrence_count') or 1)}",
                f"Normalized details: {details}",
            ]),
            "severity": severity_names.get(str(finding.get("severity")), "Info"),
            "date": str(finding.get("first_seen") or finding.get("last_seen")),
            "active": review_status not in {"false_positive", "resolved"},
            "verified": review_status == "confirmed",
            "false_p": review_status == "false_positive",
            "risk_accepted": review_status == "accepted_risk",
            "is_mitigated": review_status == "resolved",
            "unique_id_from_tool": str(finding.get("fingerprint") or "")[:500],
            "vuln_id_from_tool": (
                f"{finding.get('tool_id') or 'unknown'}:{finding.get('type') or 'finding'}"[:500]
            ),
            "nb_occurences": max(1, int(finding.get("occurrence_count") or 1)),
            "tags": ["security-platform", str(finding.get("tool_id") or "unknown")[:100]],
        }
        target = urlsplit(asset)
        if target.scheme in {"http", "https"} and target.hostname and len(asset) <= 4096:
            item["endpoints"] = [asset]
        if review_status == "resolved" and finding.get("reviewed_at"):
            item["mitigated"] = str(finding["reviewed_at"])
        exported.append(item)
    return {
        "type": "Security Testing Platform",
        "name": "Security Testing Platform normalized findings",
        "version": app.version,
        "description": "Sanitized findings exported for DefectDojo Generic Findings Import.",
        "findings": exported,
    }


@app.get("/projects/{project_id}/report.defectdojo.json")
def get_project_defectdojo_report(project_id: UUID, include_info: bool = False) -> Response:
    finding_data = get_project_findings(project_id)
    report = build_defectdojo_report(finding_data["findings"], include_info)
    return Response(
        content=json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="security-platform-{project_id}-defectdojo.json"'
            )
        },
    )


def summarize_adapter_coverage(run_coverage: list[tuple], available_adapters: list[str]) -> dict:
    available = sorted(set(available_adapters))
    available_set = set(available)
    attempted = sorted({str(row[0]) for row in run_coverage if str(row[0]) in available_set})
    successful = sorted({
        str(row[0]) for row in run_coverage
        if str(row[0]) in available_set and str(row[2]) == "succeeded" and int(row[3] or 0) > 0
    })
    unattempted = sorted(available_set - set(attempted))
    unsuccessful = sorted(set(attempted) - set(successful))
    total = len(available)
    return {
        "available_adapters": available,
        "attempted_adapters": attempted,
        "successful_adapters": successful,
        "unattempted_adapters": unattempted,
        "attempted_without_success": unsuccessful,
        "attempted_coverage_percent": round((len(attempted) / total) * 100, 1) if total else 0,
        "successful_coverage_percent": round((len(successful) / total) * 100, 1) if total else 0,
    }


def summarize_role_coverage(rows: list[tuple]) -> dict:
    profiles: dict[str, dict] = {}
    for profile_id, name, role_name, target_id, base_url, status, run_count, last_finished_at in rows:
        key = str(profile_id)
        profile = profiles.setdefault(key, {
            "id": profile_id, "name": name, "role_name": role_name,
            "target_id": target_id, "target": base_url,
            "attempted_runs": 0, "successful_runs": 0,
            "failed_runs": 0, "cancelled_runs": 0, "last_finished_at": None,
        })
        count = int(run_count or 0)
        profile["attempted_runs"] += count
        if status == "succeeded":
            profile["successful_runs"] += count
        elif status == "failed":
            profile["failed_runs"] += count
        elif status == "cancelled":
            profile["cancelled_runs"] += count
        if last_finished_at and (
            profile["last_finished_at"] is None or last_finished_at > profile["last_finished_at"]
        ):
            profile["last_finished_at"] = last_finished_at
    ordered = sorted(profiles.values(), key=lambda item: (item["role_name"].lower(), item["name"].lower()))
    total = len(ordered)
    tested = sum(item["attempted_runs"] > 0 for item in ordered)
    successful = sum(item["successful_runs"] > 0 for item in ordered)
    return {
        "profiles": ordered,
        "summary": {
            "configured_profiles": total,
            "tested_profiles": tested,
            "successful_profiles": successful,
            "untested_profiles": total - tested,
            "tested_coverage_percent": round((tested / total) * 100, 1) if total else 0,
            "successful_coverage_percent": round((successful / total) * 100, 1) if total else 0,
        },
    }


def fetch_role_coverage_rows(cursor, project_id: UUID) -> list[tuple]:
    cursor.execute(
        """
        SELECT cp.id, cp.name, cp.role_name, cp.target_id, t.base_url,
               r.status, COUNT(r.id), MAX(r.finished_at)
        FROM credential_profiles cp
        JOIN targets t ON t.id = cp.target_id
        LEFT JOIN runs r
          ON r.credential_profile_id = cp.id AND r.tool_id = 'playwright'
        WHERE cp.project_id = %s
        GROUP BY cp.id, cp.name, cp.role_name, cp.target_id, t.base_url, r.status
        ORDER BY cp.role_name, cp.name, r.status
        """,
        (project_id,),
    )
    return cursor.fetchall()


def summarize_target_coverage(rows: list[tuple], available_adapters: list[str]) -> dict:
    available = sorted(set(available_adapters))
    available_set = set(available)
    targets: dict[str, dict] = {}
    for target_id, base_url, tool_id, status, run_count, last_finished_at in rows:
        key = str(target_id)
        target = targets.setdefault(key, {
            "id": target_id, "base_url": base_url,
            "attempted_adapters": set(), "successful_adapters": set(),
            "run_count": 0, "last_finished_at": None,
        })
        if tool_id in available_set:
            target["attempted_adapters"].add(tool_id)
            if status == "succeeded" and int(run_count or 0) > 0:
                target["successful_adapters"].add(tool_id)
            target["run_count"] += int(run_count or 0)
        if last_finished_at and (
            target["last_finished_at"] is None or last_finished_at > target["last_finished_at"]
        ):
            target["last_finished_at"] = last_finished_at
    total = len(available)
    ordered = []
    for target in sorted(targets.values(), key=lambda item: item["base_url"]):
        attempted = sorted(target.pop("attempted_adapters"))
        successful = sorted(target.pop("successful_adapters"))
        ordered.append({
            **target,
            "available_adapter_count": total,
            "attempted_adapters": attempted,
            "successful_adapters": successful,
            "unattempted_adapters": sorted(available_set - set(attempted)),
            "attempted_coverage_percent": round((len(attempted) / total) * 100, 1) if total else 0,
            "successful_coverage_percent": round((len(successful) / total) * 100, 1) if total else 0,
        })
    return {"available_adapters": available, "targets": ordered}


def fetch_target_coverage_rows(cursor, project_id: UUID) -> list[tuple]:
    cursor.execute(
        """
        SELECT t.id, t.base_url, r.tool_id, r.status, COUNT(r.id), MAX(r.finished_at)
        FROM targets t
        LEFT JOIN runs r ON r.target_id = t.id
        WHERE t.project_id = %s
        GROUP BY t.id, t.base_url, r.tool_id, r.status
        ORDER BY t.base_url, r.tool_id, r.status
        """,
        (project_id,),
    )
    return cursor.fetchall()


def available_report_adapters(input_type: str | None = None) -> list[str]:
    configured = load_adapters().get("adapters", {})
    return sorted(
        name for name, adapter in configured.items()
        if name in RUNNER_IMPLEMENTED_TOOLS
        and (input_type is None or adapter.get("input", "target") == input_type)
    )


@app.get("/projects/{project_id}/adapter-coverage")
def get_project_adapter_coverage(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
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
    return {
        "project_id": project_id,
        **summarize_adapter_coverage(run_coverage, available_report_adapters()),
    }


@app.get("/projects/{project_id}/target-coverage")
def get_project_target_coverage(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            rows = fetch_target_coverage_rows(cursor, project_id)
    return {
        "project_id": project_id,
        **summarize_target_coverage(rows, available_report_adapters("target")),
    }


@app.get("/projects/{project_id}/role-coverage")
def get_project_role_coverage(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            rows = fetch_role_coverage_rows(cursor, project_id)
    return {"project_id": project_id, **summarize_role_coverage(rows)}


@app.get("/projects/{project_id}/report.json")
def get_project_json_report(project_id: UUID, include_info: bool = True) -> Response:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT name, description, created_at FROM projects WHERE id = %s",
                (project_id,),
            )
            project = cursor.fetchone()
            if project is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, base_url, allowed_hosts, excluded_paths, dns_resolver,
                       max_run_seconds, testing_window_start_minute_utc,
                       testing_window_end_minute_utc, allow_state_changing,
                       allow_third_party_services, authorization_reference, created_at
                FROM targets WHERE project_id = %s ORDER BY created_at
                """,
                (project_id,),
            )
            targets = cursor.fetchall()
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
                SELECT status, COUNT(*) FROM runs WHERE project_id = %s
                GROUP BY status ORDER BY status
                """,
                (project_id,),
            )
            status_counts = cursor.fetchall()
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
            role_coverage_rows = fetch_role_coverage_rows(cursor, project_id)
            target_coverage_rows = fetch_target_coverage_rows(cursor, project_id)

    finding_data = get_project_findings(project_id)
    findings = finding_data["findings"]
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]
    severity_counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    review_counts = {
        status: sum(1 for item in findings if item["review_status"] == status)
        for status in ("new", "confirmed", "false_positive", "accepted_risk", "resolved")
    }
    adapter_coverage = summarize_adapter_coverage(run_coverage, available_report_adapters())
    role_coverage = summarize_role_coverage(role_coverage_rows)
    target_coverage = summarize_target_coverage(
        target_coverage_rows, available_report_adapters("target")
    )
    report = {
        "schema": "security-platform-report/v1",
        "generated_at": datetime.now(timezone.utc),
        "platform_version": app.version,
        "project": {
            "id": project_id,
            "name": project[0],
            "description": project[1],
            "created_at": project[2],
        },
        "scope": {
            "targets": [
                {
                    "id": row[0],
                    "base_url": row[1],
                    "allowed_hosts": row[2],
                    "excluded_paths": row[3],
                    "dns_resolver": row[4],
                    "max_run_seconds": row[5],
                    "testing_window_utc": {
                        "start_minute": row[6],
                        "end_minute": row[7],
                        "display": format_testing_window(row[6], row[7]),
                    },
                    "allow_state_changing": row[8],
                    "allow_third_party_services": row[9],
                    "authorization_reference": row[10],
                    "created_at": row[11],
                }
                for row in targets
            ],
            "source_artifacts": [
                {
                    "filename": row[0],
                    "sha256": row[1],
                    "file_count": row[2],
                    "compressed_size": row[3],
                    "extracted_size": row[4],
                    "authorization_reference": row[5],
                    "created_at": row[6],
                }
                for row in sources
            ],
        },
        "coverage": {
            "tools_executed": sorted({row[0] for row in run_coverage}),
            "adapter_gaps": adapter_coverage,
            "role_coverage": role_coverage,
            "target_coverage": target_coverage,
            "run_status_counts": {row[0]: row[1] for row in status_counts},
            "run_matrix": [
                {
                    "tool_id": row[0],
                    "profile": row[1],
                    "status": row[2],
                    "run_count": row[3],
                    "sealed_run_count": row[4],
                    "last_finished_at": row[5],
                }
                for row in run_coverage
            ],
            "completed_runs": completed_runs,
            "sealed_runs": sealed_runs,
        },
        "summary": {
            "unique_findings": len(findings),
            "reported_findings": len(reported),
            "includes_informational": include_info,
            "severity_counts": severity_counts,
            "review_counts": review_counts,
        },
        "findings": [sanitize_evidence(item) for item in reported],
        "limitations": [
            "Automated coverage does not prove the absence of vulnerabilities.",
            "Business-logic, authorization, and exploit-chain risks may require human testing.",
            "Only saved scope, completed runs, and normalized findings are represented.",
            "Raw evidence and credentials are intentionally excluded from this export.",
        ],
    }
    return Response(
        content=json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="security-platform-{project_id}.json"'
        },
    )


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
                SELECT base_url, allowed_hosts, excluded_paths, dns_resolver,
                       max_run_seconds, testing_window_start_minute_utc,
                       testing_window_end_minute_utc, allow_state_changing,
                       allow_third_party_services, authorization_reference
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
            role_coverage_rows = fetch_role_coverage_rows(cursor, project_id)
            target_coverage_rows = fetch_target_coverage_rows(cursor, project_id)

    finding_data = get_project_findings(project_id)
    findings = finding_data["findings"]
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]
    severity_counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    review_counts = {
        status: sum(1 for item in findings if item["review_status"] == status)
        for status in ("new", "confirmed", "false_positive", "accepted_risk", "resolved")
    }

    adapter_coverage = summarize_adapter_coverage(run_coverage, available_report_adapters())
    role_coverage = summarize_role_coverage(role_coverage_rows)
    target_coverage = summarize_target_coverage(
        target_coverage_rows, available_report_adapters("target")
    )

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
        for (
            base_url, allowed_hosts, excluded_paths, dns_resolver, max_run_seconds,
            testing_window_start_minute_utc, testing_window_end_minute_utc,
            allow_state_changing, allow_third_party_services,
            authorization_reference,
        ) in targets:
            lines.extend([
                f"- Target: `{md(base_url)}`",
                f"  - Allowed hosts: {md(', '.join(allowed_hosts))}",
                f"  - Excluded paths: {md(', '.join(excluded_paths) or 'None recorded')}",
                f"  - Approved DNS resolver: {md(dns_resolver or 'None recorded')}",
                f"  - Maximum run duration: {max_run_seconds} seconds",
                "  - Testing window: "
                + format_testing_window(
                    testing_window_start_minute_utc,
                    testing_window_end_minute_utc,
                ),
                "  - State-changing extended-active tests: "
                + ("Explicitly allowed" if allow_state_changing else "Not allowed"),
                "  - Third-party intelligence/provider access: "
                + ("Explicitly allowed" if allow_third_party_services else "Not allowed"),
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
        f"- Review totals: new={review_counts['new']}, confirmed={review_counts['confirmed']}, false_positive={review_counts['false_positive']}, accepted_risk={review_counts['accepted_risk']}, resolved={review_counts['resolved']}",
        f"- Evidence sealed: {sealed_runs} of {completed_runs} completed runs",
        f"- Adapter coverage attempted: {adapter_coverage['attempted_coverage_percent']}% ({len(adapter_coverage['attempted_adapters'])} of {len(adapter_coverage['available_adapters'])})",
        f"- Adapter coverage successful: {adapter_coverage['successful_coverage_percent']}% ({len(adapter_coverage['successful_adapters'])} of {len(adapter_coverage['available_adapters'])})",
        f"- Untested adapters: {md(', '.join(adapter_coverage['unattempted_adapters']) or 'None')}",
        f"- Attempted without a successful run: {md(', '.join(adapter_coverage['attempted_without_success']) or 'None')}",
        f"- Authenticated roles tested: {role_coverage['summary']['tested_coverage_percent']}% ({role_coverage['summary']['tested_profiles']} of {role_coverage['summary']['configured_profiles']})",
        f"- Authenticated roles with a successful run: {role_coverage['summary']['successful_coverage_percent']}% ({role_coverage['summary']['successful_profiles']} of {role_coverage['summary']['configured_profiles']})",
        "",
        "### Authenticated role coverage",
        "",
        "| Profile | Role | Target | Attempts | Successful | Failed | Latest completion |",
        "|---|---|---|---:|---:|---:|---|",
    ])
    lines.extend(
        f"| {md(item['name'])} | {md(item['role_name'])} | {md(item['target'])} | {item['attempted_runs']} | {item['successful_runs']} | {item['failed_runs']} | {item['last_finished_at'].isoformat() if item['last_finished_at'] else '—'} |"
        for item in role_coverage["profiles"]
    )
    if not role_coverage["profiles"]:
        lines.append("| — | — | No authenticated profiles configured | 0 | 0 | 0 | — |")
    lines.extend([
        "",
        "### Per-target adapter coverage",
        "",
        "| Target | Attempted | Successful | Untested | Runs | Latest completion |",
        "|---|---:|---:|---:|---:|---|",
    ])
    lines.extend(
        f"| {md(item['base_url'])} | {len(item['attempted_adapters'])}/{item['available_adapter_count']} ({item['attempted_coverage_percent']}%) | {len(item['successful_adapters'])}/{item['available_adapter_count']} ({item['successful_coverage_percent']}%) | {len(item['unattempted_adapters'])} | {item['run_count']} | {item['last_finished_at'].isoformat() if item['last_finished_at'] else '—'} |"
        for item in target_coverage["targets"]
    )
    if not target_coverage["targets"]:
        lines.append("| — | 0 | 0 | 0 | 0 | No authorized targets configured |")
    lines.extend([
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
        "| Severity | Finding | Asset | Tool | Authenticated role | Occurrences | Review status |",
        "|---|---|---|---|---|---:|---|",
    ])
    lines.extend(
        f"| {md(item['severity'])} | {md(item['title'])} | {md(item['asset'])} | {md(item['tool_id'])} | {md(item.get('credential_role') or 'anonymous')} | {item['occurrence_count']} | {md(item['review_status'])} |"
        for item in reported
    )
    if not reported:
        lines.append("| — | No reportable findings | — | — | — | 0 | — |")
    else:
        lines.extend(["", "### Finding details", ""])
        for index, item in enumerate(reported, start=1):
            details = json.dumps(sanitize_evidence(item["details"]), sort_keys=True, separators=(",", ":"), default=str)
            lines.extend([
                f"#### {index}. [{md(item['severity']).upper()}] {md(item['title'])}",
                "",
                f"- Asset: `{md(item['asset'])}`",
                f"- Tool: `{md(item['tool_id'])}`",
                f"- Authenticated role: {md(item.get('credential_role') or 'anonymous')}",
                f"- Evidence run: `{md(item['run_id'])}`",
                f"- Type: `{md(item['type'])}`",
                f"- Review status: {md(item['review_status'])}",
                f"- Occurrences: {item['occurrence_count']}",
                f"- First seen: {item['first_seen'].isoformat()}",
                f"- Last seen: {item['last_seen'].isoformat()}",
                f"- Review notes: {md(item['review_notes']) or 'None'}",
                f"- Reviewed by: {md(item['reviewed_by']) or 'Not reviewed'}",
                f"- Reviewed at: {item['reviewed_at'].isoformat() if item['reviewed_at'] else 'Not reviewed'}",
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


def build_audit_export(project_id: UUID, rows: list[tuple], limit: int) -> dict:
    selected = rows[:limit]
    return {
        "schema": "security-platform-audit/v1",
        "generated_at": datetime.now(timezone.utc),
        "platform_version": app.version,
        "project_id": project_id,
        "event_count": len(selected),
        "export_limit": limit,
        "truncated": len(rows) > limit,
        "events": [
            {
                "id": row[0],
                "event_type": row[1],
                "actor": row[2],
                "object_type": row[3],
                "object_id": row[4],
                "details": sanitize_evidence(row[5]),
                "created_at": row[6],
            }
            for row in selected
        ],
    }


@app.get("/projects/{project_id}/audit-events.json")
def get_project_audit_export(project_id: UUID) -> Response:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                SELECT id, event_type, actor, object_type, object_id, details, created_at
                FROM audit_events WHERE project_id = %s
                ORDER BY created_at, id LIMIT %s
                """,
                (project_id, MAX_AUDIT_EXPORT_EVENTS + 1),
            )
            rows = cursor.fetchall()
    report = build_audit_export(project_id, rows, MAX_AUDIT_EXPORT_EVENTS)
    return Response(
        content=json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="security-platform-{project_id}-audit-events.json"'
            )
        },
    )


@app.get("/projects/{project_id}/report-bundle.zip")
def get_project_report_bundle(project_id: UUID, include_info: bool = True) -> Response:
    json_response = get_project_json_report(project_id, include_info)
    sarif_response = get_project_sarif_report(project_id, include_info)
    defectdojo_response = get_project_defectdojo_report(project_id, include_info)
    audit_response = get_project_audit_export(project_id)
    files = {
        "audit-events.json": bytes(audit_response.body),
        "report.json": bytes(json_response.body),
        "report.sarif": bytes(sarif_response.body),
        "report.defectdojo.json": bytes(defectdojo_response.body),
        "report.md": get_project_report(project_id, include_info).encode("utf-8"),
    }
    manifest = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {filename}\n"
        for filename, content in sorted(files.items())
    ).encode("ascii")
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, content in files.items():
            archive.writestr(filename, content)
        archive.writestr("manifest.sha256", manifest)
    return Response(
        content=bundle.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="security-platform-{project_id}-report-bundle.zip"'
            )
        },
    )


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
            adapter_runtime_admission(
                [tool_id], load_adapters().get("adapters", {}), enforce=True
            )
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


def apply_project_fingerprint_review(
    cursor, observation_id: UUID, status: str, notes: str, reviewed_by: str
) -> tuple | None:
    cursor.execute(
        """
        SELECT r.project_id, o.review_status, o.fingerprint
        FROM observations o JOIN runs r ON r.id = o.run_id
        WHERE o.id = %s
        """,
        (observation_id,),
    )
    observation = cursor.fetchone()
    if observation is None:
        return None
    cursor.execute(
        """
        UPDATE observations AS candidate
        SET review_status = %s, review_notes = %s, reviewed_by = %s, reviewed_at = NOW()
        FROM runs AS candidate_run
        WHERE candidate.run_id = candidate_run.id
          AND candidate_run.project_id = %s
          AND candidate.fingerprint = %s
        """,
        (status, notes, reviewed_by, observation[0], observation[2]),
    )
    affected_observations = cursor.rowcount
    cursor.execute(
        """
        SELECT run_id, review_status, review_notes, reviewed_by, reviewed_at
        FROM observations WHERE id = %s
        """,
        (observation_id,),
    )
    row = cursor.fetchone()
    return observation, row, affected_observations


@app.patch("/observations/{observation_id}")
def review_observation(observation_id: UUID, payload: ObservationReview) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            result = apply_project_fingerprint_review(
                cursor, observation_id, payload.status, payload.notes, payload.reviewed_by
            )
            if result is None:
                raise HTTPException(status_code=404, detail="Observation not found")
            observation, row, affected_observations = result
            record_audit(
                cursor, observation[0], "finding.reviewed", payload.reviewed_by,
                "observation", observation_id,
                {
                    "previous_status": observation[1],
                    "review_status": payload.status,
                    "affected_observations": affected_observations,
                },
            )
    return {
        "id": observation_id, "run_id": row[0], "review_status": row[1],
        "review_notes": row[2], "reviewed_by": row[3], "reviewed_at": row[4],
        "affected_observations": affected_observations,
    }
