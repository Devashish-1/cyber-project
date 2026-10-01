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
                """
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database()
    yield


app = FastAPI(title="Security Testing Platform", version="0.2.0", lifespan=lifespan)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)


class TargetCreate(BaseModel):
    base_url: HttpUrl
    allowed_hosts: list[str] = Field(min_length=1, max_length=50)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    authorization_reference: str = Field(min_length=3, max_length=500)
    authorization_confirmed: bool


def load_registry() -> dict:
    with REGISTRY_PATH.open("r", encoding="utf-8") as registry_file:
        return yaml.safe_load(registry_file)


@app.get("/health")
def health() -> dict[str, str]:
    with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

    cache = redis.from_url(os.environ["REDIS_URL"], socket_connect_timeout=3)
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
    with ADAPTERS_PATH.open("r", encoding="utf-8") as adapters_file:
        return yaml.safe_load(adapters_file)


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
