import json
import hashlib
import os
import shutil
import stat
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import psycopg
import redis
import yaml
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, HttpUrl

REGISTRY_PATH = Path(os.getenv("TOOL_REGISTRY_PATH", "/app/config/tools.yaml"))
ADAPTERS_PATH = Path(os.getenv("ADAPTERS_PATH", "/app/config/adapters.yaml"))
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
RUN_QUEUE = "security-platform:runs"
RUNNER_HEARTBEAT = "security-platform:runner:heartbeat"
RUNNER_IMPLEMENTED_TOOLS = {"arjun", "bandit", "brakeman", "checkov", "ffuf", "gitleaks", "hadolint", "httpx", "katana", "naabu", "nikto", "njsscan", "nmap", "nuclei-reviewed", "osv-scanner", "semgrep", "shellcheck", "subfinder", "testssl", "trivy", "trufflehog", "wapiti", "zap-passive", "zap-baseline", "zap-full"}
RUN_PLANS = {
    "observe": ["httpx", "testssl", "zap-baseline"],
    "controlled-web": ["naabu", "nmap", "httpx", "katana", "nuclei-reviewed", "nikto", "zap-baseline"],
    "extended-web": ["naabu", "nmap", "httpx", "katana", "arjun", "nuclei-reviewed", "nikto", "zap-baseline", "ffuf", "wapiti"],
}
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence/runs"))
SOURCE_ROOT = Path(os.getenv("SOURCE_ROOT", "/sources"))
MAX_SOURCE_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_SOURCE_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_SOURCE_FILES = 5_000
MAX_EVIDENCE_BYTES = 1_048_576
MAX_EVIDENCE_LINES = 200
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
                    authorization_reference TEXT NOT NULL,
                    authorization_confirmed BOOLEAN NOT NULL CHECK (authorization_confirmed),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
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
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS batch_id UUID;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS batch_step INTEGER;
                ALTER TABLE runs ADD COLUMN IF NOT EXISTS retest_of_observation UUID;
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


app = FastAPI(title="Security Testing Platform", version="0.42.0", lifespan=lifespan)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)


class TargetCreate(BaseModel):
    base_url: HttpUrl
    allowed_hosts: list[str] = Field(min_length=1, max_length=50)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    authorization_reference: str = Field(min_length=3, max_length=500)
    authorization_confirmed: bool


class RunCreate(BaseModel):
    target_id: UUID | None = None
    source_artifact_id: UUID | None = None
    tool_id: str = Field(min_length=1, max_length=100)
    profile: str = Field(min_length=1, max_length=100)
    requested_by: str = Field(min_length=2, max_length=120)
    approval_confirmed: bool


class BatchCreate(BaseModel):
    target_id: UUID
    plan_id: str = Field(pattern="^(observe|controlled-web|extended-web)$")
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
    disk = shutil.disk_usage(EVIDENCE_ROOT)
    return {
        "runner": runner,
        "runner_heartbeat_age_seconds": round(heartbeat_age, 1) if heartbeat_age is not None else None,
        "queue_depth": cache.llen(RUN_QUEUE),
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
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "security-testing-platform-api", "status": "ready"}


@app.post("/emergency-stop", status_code=202)
def emergency_stop(payload: EmergencyStopCreate) -> dict:
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
    cache = queue_client()
    for run_id, _, _ in changed:
        cache.publish("security-platform:cancellations", str(run_id))
    return {
        "status": "stop-requested",
        "changed": [
            {"run_id": row[0], "project_id": row[1], "status": row[2]}
            for row in changed
        ],
    }


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

    target_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Project not found")
            cursor.execute(
                """
                INSERT INTO targets
                    (id, project_id, base_url, allowed_hosts, excluded_paths,
                     authorization_reference, authorization_confirmed)
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s, TRUE)
                """,
                (
                    target_id,
                    project_id,
                    str(payload.base_url),
                    Jsonb(payload.allowed_hosts),
                    Jsonb(payload.excluded_paths),
                    payload.authorization_reference,
                ),
            )
            record_audit(
                cursor, project_id, "target.authorized", "system", "target", target_id,
                {"base_url": str(payload.base_url), "authorization_reference": payload.authorization_reference},
            )
    return {"id": target_id, "project_id": project_id, **payload.model_dump(mode="json")}


@app.get("/projects/{project_id}/targets")
def list_targets(project_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, base_url, allowed_hosts, excluded_paths,
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
                "excluded_paths": row[3], "authorization_reference": row[4],
                "authorization_confirmed": row[5], "created_at": row[6],
            }
            for row in rows
        ]
    }


@app.post("/projects/{project_id}/runs", status_code=202)
def create_run(project_id: UUID, payload: RunCreate) -> dict:
    if not payload.approval_confirmed:
        raise HTTPException(status_code=422, detail="Explicit run approval is required")

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
    input_type = adapter.get("input", "target")
    if input_type == "source":
        if payload.source_artifact_id is None or payload.target_id is not None:
            raise HTTPException(status_code=422, detail="This adapter requires exactly one source artifact")
    elif payload.target_id is None or payload.source_artifact_id is not None:
        raise HTTPException(status_code=422, detail="This adapter requires exactly one authorized target")

    run_id = uuid4()
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
            cursor.execute(
                """
                INSERT INTO runs
                    (id, project_id, target_id, source_artifact_id, tool_id, profile, status, requested_by)
                VALUES (%s, %s, %s, %s, %s, %s, 'queued', %s)
                """,
                (
                    run_id, project_id, payload.target_id, payload.source_artifact_id,
                    payload.tool_id, payload.profile, payload.requested_by,
                ),
            )
            record_audit(
                cursor, project_id, "run.approved", payload.requested_by, "run", run_id,
                {
                    "target_id": str(payload.target_id) if payload.target_id else None,
                    "source_artifact_id": str(payload.source_artifact_id) if payload.source_artifact_id else None,
                    "tool_id": payload.tool_id, "profile": payload.profile,
                },
            )

    queue_client().rpush(RUN_QUEUE, str(run_id))
    return {"id": run_id, "status": "queued", **payload.model_dump(mode="json")}


@app.post("/projects/{project_id}/batches", status_code=202)
def create_batch(project_id: UUID, payload: BatchCreate) -> dict:
    if not payload.approval_confirmed:
        raise HTTPException(status_code=422, detail="Explicit batch approval is required")
    tool_ids = RUN_PLANS[payload.plan_id]
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
            cursor.execute(
                """
                INSERT INTO run_batches (id, project_id, target_id, plan_id, requested_by)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (batch_id, project_id, payload.target_id, payload.plan_id, payload.requested_by),
            )
            cursor.executemany(
                """
                INSERT INTO runs
                    (id, project_id, target_id, tool_id, profile, status, requested_by, batch_id, batch_step)
                VALUES (%s, %s, %s, %s, %s, 'queued', %s, %s, %s)
                """,
                [
                    (
                        run_id, project_id, payload.target_id, tool_id,
                        adapters[tool_id]["profile"], payload.requested_by, batch_id, batch_step,
                    )
                    for batch_step, (run_id, tool_id) in enumerate(zip(run_ids, tool_ids), start=1)
                ],
            )
            record_audit(
                cursor, project_id, "workflow.approved", payload.requested_by, "batch", batch_id,
                {"target_id": str(payload.target_id), "plan_id": payload.plan_id, "tools": tool_ids},
            )

    queue = queue_client()
    queue.rpush(RUN_QUEUE, *[str(run_id) for run_id in run_ids])
    return {
        "id": batch_id,
        "status": "queued",
        "plan_id": payload.plan_id,
        "target_id": payload.target_id,
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
                "requested_by": row[3], "created_at": row[4],
                "status": derive_batch_status(list(row[5])),
                "status_counts": {status: list(row[5]).count(status) for status in sorted(set(row[5]))},
            }
            for row in rows
        ]
    }


@app.get("/batches/{batch_id}")
def get_batch(batch_id: UUID) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, project_id, target_id, plan_id, requested_by, created_at FROM run_batches WHERE id = %s",
                (batch_id,),
            )
            batch = cursor.fetchone()
            if batch is None:
                raise HTTPException(status_code=404, detail="Batch not found")
            cursor.execute(
                """
                SELECT id, project_id, target_id, tool_id, profile, status,
                       requested_by, error_message, created_at, started_at, finished_at,
                       retest_of_observation, source_artifact_id
                FROM runs WHERE batch_id = %s ORDER BY batch_step, created_at
                """,
                (batch_id,),
            )
            runs = [run_row(row) for row in cursor.fetchall()]
    return {
        "id": batch[0], "project_id": batch[1], "target_id": batch[2],
        "plan_id": batch[3], "requested_by": batch[4], "created_at": batch[5],
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
                       retest_of_observation, source_artifact_id
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
                       retest_of_observation, source_artifact_id
                FROM runs WHERE id = %s
                """,
                (run_id,),
            )
            row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run_row(row)


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
            cursor.execute("SELECT status FROM runs WHERE id = %s", (run_id,))
            row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")

    run_directory = EVIDENCE_ROOT / str(run_id)
    return {
        "run_id": run_id,
        "status": row[0],
        "metadata": read_json_file(run_directory / "metadata.json"),
        "events": read_jsonl_file(run_directory / "events.jsonl"),
        "output": read_jsonl_file(run_directory / "output.jsonl"),
        "limits": {"max_bytes_per_file": MAX_EVIDENCE_BYTES, "max_lines_per_file": MAX_EVIDENCE_LINES},
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
            cursor.execute("SELECT tool_id, status FROM runs WHERE id = %s", (run_id,))
            run = cursor.fetchone()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if run[0] != "trivy":
        raise HTTPException(status_code=409, detail="This run does not produce an SBOM")
    sbom_path = EVIDENCE_ROOT / str(run_id) / "sbom.cdx.json"
    if not sbom_path.is_file():
        raise HTTPException(status_code=404, detail="SBOM is not available for this run")
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
                SELECT base_url, allowed_hosts, excluded_paths, authorization_reference
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

    finding_data = get_project_findings(project_id)
    findings = finding_data["findings"]
    reported = findings if include_info else [item for item in findings if item["severity"] != "info"]
    severity_counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }

    def md(value: object) -> str:
        return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    lines = [
        f"# Security assessment report — {md(project[0])}",
        "",
        f"Project ID: `{project_id}`  ",
        f"Created: {project[2].isoformat()}  ",
        f"Description: {md(project[1]) or 'Not provided'}",
        "",
        "## Scope and authorization",
        "",
    ]
    if targets:
        for base_url, allowed_hosts, excluded_paths, authorization_reference in targets:
            lines.extend([
                f"- Target: `{md(base_url)}`",
                f"  - Allowed hosts: {md(', '.join(allowed_hosts))}",
                f"  - Excluded paths: {md(', '.join(excluded_paths) or 'None recorded')}",
                f"  - Authorization reference: {md(authorization_reference)}",
            ])
    else:
        lines.append("No targets recorded.")
    lines.extend([
        "",
        "## Automated coverage",
        "",
        f"- Tools executed: {md(', '.join(tools) or 'None')}",
        f"- Run outcomes: {md(', '.join(f'{status}={count}' for status, count in status_counts) or 'None')}",
        f"- Unique observations: {len(findings)}",
        f"- Severity totals: critical={severity_counts['critical']}, high={severity_counts['high']}, medium={severity_counts['medium']}, low={severity_counts['low']}, info={severity_counts['info']}",
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
    run_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.project_id, r.target_id, r.source_artifact_id, r.tool_id, r.profile,
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
            project_id, target_id, source_artifact_id, tool_id, profile, input_authorized = origin
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
                    (id, project_id, target_id, source_artifact_id, tool_id, profile,
                     status, requested_by, retest_of_observation)
                VALUES (%s, %s, %s, %s, %s, %s, 'queued', %s, %s)
                """,
                (
                    run_id, project_id, target_id, source_artifact_id, tool_id, profile,
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
                    "tool_id": tool_id, "profile": profile,
                },
            )
    queue_client().rpush(RUN_QUEUE, str(run_id))
    return {
        "id": run_id, "status": "queued", "project_id": project_id,
        "target_id": target_id, "source_artifact_id": source_artifact_id,
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
