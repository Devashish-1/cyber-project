import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import redis
import yaml
from fastapi import FastAPI, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, HttpUrl

REGISTRY_PATH = Path(os.getenv("TOOL_REGISTRY_PATH", "/app/config/tools.yaml"))
ADAPTERS_PATH = Path(os.getenv("ADAPTERS_PATH", "/app/config/adapters.yaml"))
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
RUN_QUEUE = "security-platform:runs"
RUNNER_IMPLEMENTED_TOOLS = {"ffuf", "httpx", "katana", "nikto", "nuclei-reviewed", "subfinder", "testssl", "wapiti", "zap-baseline", "zap-full"}
RUN_PLANS = {
    "observe": ["httpx", "testssl", "zap-baseline"],
    "controlled-web": ["httpx", "katana", "nuclei-reviewed", "nikto", "zap-baseline"],
    "extended-web": ["httpx", "katana", "nuclei-reviewed", "nikto", "zap-baseline", "ffuf", "wapiti"],
}
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence/runs"))
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
                """
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database()
    yield


app = FastAPI(title="Security Testing Platform", version="0.20.1", lifespan=lifespan)


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
    target_id: UUID
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


def load_registry() -> dict:
    with REGISTRY_PATH.open("r", encoding="utf-8") as registry_file:
        return yaml.safe_load(registry_file)


def load_adapters() -> dict:
    with ADAPTERS_PATH.open("r", encoding="utf-8") as adapters_file:
        return yaml.safe_load(adapters_file)


def queue_client() -> redis.Redis:
    return redis.from_url(REDIS_URL, socket_connect_timeout=3, decode_responses=True)


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


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "security-testing-platform-api", "status": "ready"}


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


@app.post("/projects/{project_id}/targets", status_code=201)
def create_target(project_id: UUID, payload: TargetCreate) -> dict:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Explicit target authorization confirmation is required")

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

    run_id = uuid4()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT authorization_confirmed
                FROM targets
                WHERE id = %s AND project_id = %s
                """,
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
                    (id, project_id, target_id, tool_id, profile, status, requested_by)
                VALUES (%s, %s, %s, %s, %s, 'queued', %s)
                """,
                (run_id, project_id, payload.target_id, payload.tool_id, payload.profile, payload.requested_by),
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
                       requested_by, error_message, created_at, started_at, finished_at
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
            cursor.execute("SELECT 1 FROM run_batches WHERE id = %s", (batch_id,))
            if cursor.fetchone() is None:
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
                       requested_by, error_message, created_at, started_at, finished_at
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
                       requested_by, error_message, created_at, started_at, finished_at
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
            cursor.execute("SELECT status FROM runs WHERE id = %s FOR UPDATE", (run_id,))
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


@app.patch("/observations/{observation_id}")
def review_observation(observation_id: UUID, payload: ObservationReview) -> dict:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
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
    if row is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    return {
        "id": observation_id, "run_id": row[0], "review_status": row[1],
        "review_notes": row[2], "reviewed_by": row[3], "reviewed_at": row[4],
    }
