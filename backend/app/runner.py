import json
import hashlib
import ipaddress
import re
import io
import os
import tarfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import UUID
from uuid import uuid4
from urllib.parse import urlsplit

import docker
import psycopg
import redis
import yaml

DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
ADAPTERS_PATH = Path(os.getenv("ADAPTERS_PATH", "/app/config/adapters.yaml"))
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence/runs"))
SOURCE_ROOT = Path(os.getenv("SOURCE_ROOT", "/sources"))
SOURCE_HOST_ROOT = Path(os.getenv("SOURCE_HOST_ROOT", "/home/killswitch/security-platform/data/sources"))
TRIVY_CACHE_HOST_PATH = os.getenv(
    "TRIVY_CACHE_HOST_PATH",
    "/home/killswitch/security-platform/data/trivy-cache",
)
SEMGREP_RULES_HOST_PATH = os.getenv(
    "SEMGREP_RULES_HOST_PATH",
    "/home/killswitch/security-platform/config/semgrep-reviewed.yaml",
)
NUCLEI_TEMPLATES_HOST_PATH = os.getenv(
    "NUCLEI_TEMPLATES_HOST_PATH",
    "/home/killswitch/security-platform/config/templates/nuclei-upstream",
)
FFUF_WORDLIST_HOST_PATH = os.getenv(
    "FFUF_WORDLIST_HOST_PATH",
    "/home/killswitch/security-platform/config/wordlists/content-reviewed-small.txt",
)
FFUF_WORDLIST_RUNNER_PATH = Path(
    os.getenv("FFUF_WORDLIST_RUNNER_PATH", "/app/config/wordlists/content-reviewed-small.txt")
)
ARJUN_WORDLIST_HOST_PATH = os.getenv(
    "ARJUN_WORDLIST_HOST_PATH",
    "/home/killswitch/security-platform/config/wordlists/parameters-reviewed-small.txt",
)
RUN_QUEUE = "security-platform:runs"
RUNNER_HEARTBEAT = "security-platform:runner:heartbeat"
RUNNER_HEARTBEAT_TTL = 15
POLL_SECONDS = 1.0


def heartbeat_loop() -> None:
    heartbeat = redis.from_url(
        REDIS_URL,
        socket_connect_timeout=5,
        socket_timeout=10,
        decode_responses=True,
    )
    while True:
        try:
            heartbeat.set(RUNNER_HEARTBEAT, str(time.time()), ex=RUNNER_HEARTBEAT_TTL)
        except redis.RedisError as exc:
            print(f"runner heartbeat error: {exc}", flush=True)
        time.sleep(5)


def load_adapters() -> dict:
    with ADAPTERS_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle).get("adapters", {})


def set_status(run_id: UUID, status: str, error: str | None = None) -> None:
    timestamps = {
        "running": "started_at = NOW()",
        "cancelled": "finished_at = NOW()",
        "succeeded": "finished_at = NOW()",
        "failed": "finished_at = NOW()",
    }
    timestamp = timestamps.get(status, "finished_at = finished_at")
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE runs SET status = %s, error_message = %s, {timestamp} WHERE id = %s",
                (status, error, run_id),
            )


def get_run(run_id: UUID) -> dict | None:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.status, r.tool_id, r.profile, t.base_url, t.allowed_hosts,
                       t.excluded_paths,
                       COALESCE(t.authorization_confirmed, s.authorization_confirmed, FALSE),
                       r.source_artifact_id, s.filename, s.sha256
                FROM runs r
                LEFT JOIN targets t ON t.id = r.target_id
                LEFT JOIN source_artifacts s ON s.id = r.source_artifact_id
                WHERE r.id = %s
                """,
                (run_id,),
            )
            row = cursor.fetchone()
    if row is None:
        return None
    return {
        "status": row[0],
        "tool_id": row[1],
        "profile": row[2],
        "base_url": row[3],
        "allowed_hosts": row[4],
        "excluded_paths": row[5],
        "authorization_confirmed": row[6],
        "source_artifact_id": row[7],
        "source_filename": row[8],
        "source_sha256": row[9],
    }


def build_command(
    tool_id: str,
    base_url: str | None,
    adapter: dict | None = None,
    excluded_paths: list[str] | None = None,
) -> list[str]:
    if tool_id == "trufflehog":
        return [
            "--json",
            "--no-verification",
            "--no-update",
            "--concurrency=1",
            "--results=unverified",
            "--force-skip-binaries",
            "--force-skip-archives",
            "filesystem", "/src",
        ]
    if tool_id == "bandit":
        return [
            "-r", "/src",
            "-f", "json",
            "-q",
            "--severity-level", "all",
            "--confidence-level", "all",
            "--exit-zero",
            "-x", "/src/.git,/src/node_modules,/src/vendor,/src/.venv,/src/venv",
        ]
    if tool_id == "checkov":
        return [
            "--directory", "/src",
            "--output", "json",
            "--quiet",
            "--compact",
            "--skip-download",
            "--download-external-modules", "false",
            "--soft-fail",
        ]
    if tool_id == "gitleaks":
        return [
            "detect",
            "--source", "/src",
            "--no-git",
            "--no-banner",
            "--redact", "100",
            "--report-format", "json",
            "--report-path=-",
            "--exit-code", "1",
        ]
    if tool_id == "semgrep":
        return [
            "semgrep", "scan",
            "--config", "/rules/semgrep-reviewed.yaml",
            "--json",
            "--quiet",
            "--metrics", "off",
            "--disable-version-check",
            "--jobs", "1",
            "--timeout", "5",
            "--timeout-threshold", "3",
            "--max-memory", "768",
            "--max-target-bytes", "1000000",
            "--exclude", ".git",
            "--exclude", "node_modules",
            "--exclude", "vendor",
            "--exclude", "*.min.js",
            "/src",
        ]
    if tool_id == "trivy":
        return [
            "-c",
            "set -eu; "
            "trivy fs --cache-dir /cache --skip-db-update --skip-java-db-update "
            "--skip-check-update --offline-scan --scanners vuln,misconfig,secret,license "
            "--format json --output /tmp/trivy.json --parallel 1 --timeout 5m "
            "--exit-code 0 /src; "
            "trivy fs --cache-dir /cache --skip-db-update --skip-java-db-update "
            "--skip-check-update --offline-scan --scanners vuln --format cyclonedx "
            "--output /tmp/sbom.cdx.json --parallel 1 --timeout 5m /src; "
            "touch /tmp/.reports-ready; sleep 600",
        ]
    if tool_id == "httpx":
        return [
            "-u", base_url,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-tls-grab",
            "-follow-host-redirects",
            "-max-redirects", "3",
            "-rate-limit", "5",
            "-timeout", "10",
            "-retries", "1",
        ]
    if tool_id == "naabu":
        hostname = urlsplit(base_url).hostname
        if not hostname:
            raise ValueError("Naabu target does not contain a hostname")
        return [
            "-host", hostname,
            "-scan-type", "c",
            "-top-ports", "100",
            "-rate", "50",
            "-c", "5",
            "-timeout", "1000",
            "-retries", "1",
            "-verify",
            "-Pn",
            "-json",
            "-silent",
            "-disable-update-check",
        ]
    if tool_id == "nmap":
        hostname = urlsplit(base_url).hostname
        if not hostname:
            raise ValueError("Nmap target does not contain a hostname")
        return [
            "-sT",
            "-sV",
            "--version-light",
            "-T2",
            "--max-rate", "20",
            "--max-retries", "1",
            "--host-timeout", "120s",
            "--top-ports", "20",
            "-Pn",
            "-n",
            "-oX", "-",
            hostname,
        ]
    if tool_id == "testssl":
        return [
            "--quiet",
            "--warnings", "batch",
            "--connect-timeout", "10",
            "--openssl-timeout", "10",
            "-oJ", "/tmp/testssl.json",
            base_url,
        ]
    if tool_id == "nuclei-reviewed":
        reviewed_templates = (adapter or {}).get("templates") or []
        if not reviewed_templates:
            raise ValueError("Nuclei reviewed template allowlist is empty")
        template_args = [value for path in reviewed_templates for value in ("-t", f"/templates/{path}")]
        return [
            "-u", base_url,
            *template_args,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-disable-unsigned-templates",
            "-no-interactsh",
            "-severity", "info,low,medium,high,critical",
            "-rate-limit", "5",
            "-bulk-size", "10",
            "-concurrency", "2",
            "-timeout", "10",
            "-retries", "1",
        ]
    if tool_id == "subfinder":
        hostname = urlsplit(base_url).hostname
        if not hostname:
            raise ValueError("Subfinder target does not contain a hostname")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("Subfinder requires an authorized DNS domain, not an IP address")
        return [
            "-d", hostname,
            "-json",
            "-collect-sources",
            "-silent",
            "-disable-update-check",
            "-rate-limit", "5",
            "-timeout", "15",
            "-max-time", "5",
        ]
    if tool_id == "nikto":
        return [
            "-h", base_url,
            "-Tuning", "123",
            "-maxtime", "5m",
            "-Pause", "0.05",
            "-nointeractive",
            "-nocheck",
            "-Display", "E",
        ]
    if tool_id == "katana":
        exclusion_args = [
            value
            for path in (excluded_paths or [])
            if path and path.startswith("/")
            for value in ("-crawl-out-scope", f".*{re.escape(path)}.*")
        ]
        return [
            "-u", base_url,
            "-jsonl",
            "-silent",
            "-omit-raw",
            "-omit-body",
            "-depth", "2",
            "-crawl-duration", "2m",
            "-rate-limit", "5",
            "-host-rate-limit", "5",
            "-field-scope", "fqdn",
            "-disable-update-check",
            *exclusion_args,
        ]
    if tool_id == "wapiti":
        return [
            "-u", base_url,
            "--scope", "url",
            "-m", "wapp,methods,csrf",
            "--max-scan-time", "120",
            "--max-links-per-page", "50",
            "--max-files-per-dir", "50",
            "--tasks", "2",
            "-t", "10",
            "-f", "json",
            "-o", "/tmp/report.json",
            "--no-bugreport",
            "-v", "0",
        ]
    if tool_id == "ffuf":
        candidates = [
            f"/{line.strip().lstrip('/')}"
            for line in FFUF_WORDLIST_RUNNER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for excluded in (excluded_paths or []):
            normalized = excluded.rstrip("/") or "/"
            if any(candidate == normalized or candidate.startswith(f"{normalized}/") for candidate in candidates):
                raise ValueError(f"Reviewed ffuf wordlist intersects excluded path: {excluded}")
        return [
            "-w", "/wordlists/content.txt",
            "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-json",
            "-s",
            "-noninteractive",
            "-rate", "5",
            "-t", "2",
            "-timeout", "10",
            "-maxtime", "120",
            "-mc", "all",
            "-fc", "404",
        ]
    if tool_id == "arjun":
        return [
            "-u", base_url,
            "-oJ", "/tmp/arjun.json",
            "-w", "/wordlists/parameters.txt",
            "-m", "GET",
            "-t", "2",
            "-d", "0.2",
            "--rate-limit", "5",
            "-T", "10",
            "-c", "10",
            "--stable",
            "--disable-redirects",
            "-q",
        ]
    if tool_id == "zap-baseline":
        return [
            "-t", base_url,
            "-J", "report.json",
            "-m", "1",
            "-T", "5",
            "-I",
            "-s",
            "--autooff",
        ]
    if tool_id == "zap-full":
        return [
            "-t", base_url,
            "-J", "report.json",
            "-m", "2",
            "-T", "15",
            "-I",
            "-s",
        ]
    raise ValueError(f"Runner does not implement adapter: {tool_id}")


def append_event(event_file: Path, event: dict) -> None:
    event_file.parent.mkdir(parents=True, exist_ok=True)
    with event_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def normalize_httpx(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            asset = str(item.get("url") or item.get("input") or "")[:2000]
            if not asset:
                continue
            details = {
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "webserver": item.get("webserver"),
                "content_type": item.get("content_type"),
                "host_ip": item.get("host_ip"),
                "port": item.get("port"),
                "technologies": item.get("tech") or [],
            }
            fingerprint = hashlib.sha256(f"http-service|{asset}".encode()).hexdigest()
            records.append((uuid4(), run_id, "http-service", "HTTP service observed", "info", asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_naabu(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            host = str(item.get("host") or item.get("ip") or "")[:1000]
            ip = str(item.get("ip") or host)[:1000]
            port = int(item.get("port") or 0)
            if not host or not (1 <= port <= 65535):
                continue
            asset = f"{host}:{port}"[:2000]
            details = {
                "host": host,
                "ip": ip,
                "port": port,
                "protocol": item.get("protocol") or "tcp",
                "tls": bool(item.get("tls")),
            }
            fingerprint = hashlib.sha256(f"open-port|{ip}|{port}|tcp".encode()).hexdigest()
            records.append((uuid4(), run_id, "open-port", "TCP port observed open", "info", asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_nmap(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        raw = output_file.read_text(encoding="utf-8", errors="replace")
        xml_start = raw.find("<?xml")
        if xml_start < 0:
            return 0
        root = ET.fromstring(raw[xml_start:])
        for host_node in root.findall("host"):
            address_node = host_node.find("address")
            address = (address_node.get("addr") if address_node is not None else "") or "network-target"
            for port_node in host_node.findall("./ports/port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                port = int(port_node.get("portid") or 0)
                protocol = port_node.get("protocol") or "tcp"
                if not (1 <= port <= 65535):
                    continue
                service_node = port_node.find("service")
                service = service_node.attrib if service_node is not None else {}
                product = " ".join(
                    str(service.get(key) or "").strip()
                    for key in ("product", "version", "extrainfo")
                ).strip()
                asset = f"{address}:{port}"[:2000]
                details = {
                    "address": address,
                    "port": port,
                    "protocol": protocol,
                    "service": service.get("name"),
                    "product": product,
                    "tunnel": service.get("tunnel"),
                    "method": service.get("method"),
                    "confidence": service.get("conf"),
                }
                fingerprint = hashlib.sha256(f"network-service|{address}|{port}|{protocol}".encode()).hexdigest()
                records.append((uuid4(), run_id, "network-service", "TCP service identified", "info", asset, json.dumps(details), fingerprint))
    except (OSError, ET.ParseError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_nuclei(run_id: UUID, output_file: Path) -> int:
    allowed_severities = {"info", "low", "medium", "high", "critical"}
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            info = item.get("info") or {}
            template_id = str(item.get("template-id") or "nuclei-template")[:200]
            matcher = str(item.get("matcher-name") or item.get("type") or "match")[:200]
            asset = str(item.get("matched-at") or item.get("host") or "HTTP target")[:2000]
            severity = str(info.get("severity") or "info").lower()
            if severity not in allowed_severities:
                severity = "info"
            title = str(info.get("name") or template_id)[:500]
            details = {
                "template_id": template_id,
                "template_url": item.get("template-url"),
                "matcher": matcher,
                "type": item.get("type"),
                "host": item.get("host"),
                "ip": item.get("ip"),
                "port": item.get("port"),
                "scheme": item.get("scheme"),
                "tags": info.get("tags") or [],
                "description": info.get("description"),
                "reference": info.get("reference") or [],
                "classification": info.get("classification") or {},
                "extracted_results": item.get("extracted-results") or [],
            }
            fingerprint = hashlib.sha256(
                f"nuclei|{template_id}|{matcher}|{asset}".encode()
            ).hexdigest()
            records.append((uuid4(), run_id, "nuclei-finding", title, severity, asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_subfinder(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            hostname = str(item.get("host") or "").lower().rstrip(".")[:2000]
            root_domain = str(item.get("input") or "").lower().rstrip(".")[:2000]
            if not hostname or not root_domain or not (
                hostname == root_domain or hostname.endswith(f".{root_domain}")
            ):
                continue
            sources = item.get("sources") or ([item.get("source")] if item.get("source") else [])
            details = {"root_domain": root_domain, "sources": sources}
            fingerprint = hashlib.sha256(f"subdomain|{hostname}".encode()).hexdigest()
            records.append((uuid4(), run_id, "subdomain", "Subdomain discovered", "info", hostname, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_nikto(run_id: UUID, output_file: Path) -> int:
    finding_pattern = re.compile(r"^\+ \[(?P<test_id>[^]]+)\] (?P<path>\S+): (?P<message>.+)$")
    target = "HTTP target"
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line.startswith("+ Target Hostname:"):
                target = line.split(":", 1)[1].strip()[:2000]
                continue
            match = finding_pattern.match(line)
            if not match:
                continue
            test_id = match.group("test_id")[:200]
            path = match.group("path")[:2000]
            message = match.group("message")[:4000]
            asset = f"{target}{path}"[:2000]
            severity = "low" if "missing" in message.lower() or "misconfig" in message.lower() else "info"
            details = {"test_id": test_id, "path": path, "message": message}
            fingerprint = hashlib.sha256(f"nikto|{test_id}|{asset}|{message}".encode()).hexdigest()
            records.append((uuid4(), run_id, "nikto-finding", "Nikto web-server finding", severity, asset, json.dumps(details), fingerprint))
    except OSError:
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_katana(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            request = item.get("request") or {}
            response = item.get("response") or {}
            endpoint = str(request.get("endpoint") or "")[:2000]
            if not endpoint:
                continue
            method = str(request.get("method") or "GET")[:20]
            details = {
                "method": method,
                "status_code": response.get("status_code"),
                "content_type": (response.get("headers") or {}).get("Content-Type"),
                "content_length": response.get("content_length"),
            }
            fingerprint = hashlib.sha256(f"endpoint|{method}|{endpoint}".encode()).hexdigest()
            records.append((uuid4(), run_id, "http-endpoint", "HTTP endpoint discovered", "info", endpoint, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_wapiti(run_id: UUID, output_file: Path) -> int:
    severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    section_types = {
        "vulnerabilities": "wapiti-vulnerability",
        "anomalies": "wapiti-anomaly",
        "additionals": "wapiti-additional",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for section, observation_type in section_types.items():
            for category, findings in (report.get(section) or {}).items():
                for finding in findings or []:
                    method = str(finding.get("method") or "GET")[:20]
                    path = str(finding.get("path") or "/")[:2000]
                    module = str(finding.get("module") or "wapiti")[:200]
                    raw_info = finding.get("info")
                    try:
                        parsed_info = json.loads(raw_info) if isinstance(raw_info, str) else raw_info
                    except json.JSONDecodeError:
                        parsed_info = raw_info
                    severity = severity_map.get(int(finding.get("level") or 0), "info")
                    details = {
                        "category": category,
                        "module": module,
                        "method": method,
                        "path": path,
                        "parameter": finding.get("parameter"),
                        "info": parsed_info,
                        "wstg": finding.get("wstg") or [],
                    }
                    fingerprint = hashlib.sha256(
                        f"wapiti|{section}|{category}|{module}|{method}|{path}".encode()
                    ).hexdigest()
                    records.append((uuid4(), run_id, observation_type, str(category)[:500], severity, path, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_ffuf(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            url = str(item.get("url") or "")[:2000]
            if not url:
                continue
            status = int(item.get("status") or 0)
            details = {
                "status_code": status,
                "content_type": item.get("content-type"),
                "content_length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "redirect_location": item.get("redirectlocation"),
            }
            fingerprint = hashlib.sha256(f"content-path|{url}|{status}".encode()).hexdigest()
            records.append((uuid4(), run_id, "content-path", "Content path discovered", "info", url, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_arjun(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        if not isinstance(report, dict):
            return 0
        for target, raw_parameters in report.items():
            if isinstance(raw_parameters, dict):
                parameters = list(raw_parameters)
            elif isinstance(raw_parameters, list):
                parameters = raw_parameters
            else:
                continue
            for raw_parameter in parameters:
                parameter = str(raw_parameter).strip()[:200]
                if not parameter:
                    continue
                asset = str(target)[:2000]
                details = {"parameter": parameter, "method": "GET", "source": "active-comparison"}
                fingerprint = hashlib.sha256(f"http-parameter|GET|{asset}|{parameter}".encode()).hexdigest()
                records.append((uuid4(), run_id, "http-parameter", "HTTP GET parameter discovered", "info", asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def capture_testssl_output(container, output_file: Path) -> None:
    stream, _ = container.get_archive("/tmp")
    archive = io.BytesIO(b"".join(stream))
    with tarfile.open(fileobj=archive, mode="r:*") as tar:
        member = next((item for item in tar.getmembers() if item.isfile() and item.name.lower().endswith(".json")), None)
        if member is None:
            raise RuntimeError("testssl JSON output was not found in /tmp")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise RuntimeError("testssl JSON output could not be read")
        payload = json.loads(extracted.read().decode("utf-8"))
    records = payload if isinstance(payload, list) else [payload]
    output_file.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


def capture_json_output(container, container_path: str, output_file: Path) -> None:
    stream, _ = container.get_archive(container_path)
    archive = io.BytesIO(b"".join(stream))
    with tarfile.open(fileobj=archive, mode="r:*") as tar:
        member = next((item for item in tar.getmembers() if item.isfile()), None)
        if member is None:
            raise RuntimeError(f"JSON output was not found: {container_path}")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"JSON output could not be read: {container_path}")
        payload = json.loads(extracted.read().decode("utf-8"))
    output_file.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")


def write_gitleaks_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    if isinstance(payload, list):
        for finding in payload:
            if isinstance(finding, dict):
                for key in list(finding):
                    if key.lower() in {"secret", "match"}:
                        finding[key] = "[REDACTED]"
    output_file.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")


def write_semgrep_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    sanitized_results = []
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        extra = result.get("extra") or {}
        sanitized_results.append(
            {
                "check_id": result.get("check_id"),
                "path": result.get("path"),
                "start": {
                    "line": (result.get("start") or {}).get("line"),
                    "col": (result.get("start") or {}).get("col"),
                },
                "end": {
                    "line": (result.get("end") or {}).get("line"),
                    "col": (result.get("end") or {}).get("col"),
                },
                "extra": {
                    "message": extra.get("message"),
                    "severity": extra.get("severity"),
                    "metadata": extra.get("metadata") or {},
                },
            }
        )
    sanitized = {
        "version": payload.get("version") if isinstance(payload, dict) else None,
        "results": sanitized_results,
        "errors": [
            {"type": error.get("type"), "level": error.get("level"), "message": "[OMITTED]"}
            for error in (payload.get("errors", []) if isinstance(payload, dict) else [])
            if isinstance(error, dict)
        ],
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def write_checkov_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    frameworks = payload if isinstance(payload, list) else [payload]
    sanitized = []
    for framework in frameworks:
        if not isinstance(framework, dict):
            continue
        results = framework.get("results") or {}
        failures = []
        for finding in results.get("failed_checks") or []:
            if not isinstance(finding, dict):
                continue
            failures.append({key: finding.get(key) for key in (
                "check_id", "bc_check_id", "check_name", "file_path",
                "file_line_range", "resource", "guideline", "severity",
            )})
        sanitized.append(
            {
                "check_type": framework.get("check_type"),
                "results": {"failed_checks": failures},
                "summary": framework.get("summary") or {},
            }
        )
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def write_bandit_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    results = []
    for finding in payload.get("results", []) if isinstance(payload, dict) else []:
        filename = str(finding.get("filename") or "source")
        if filename.startswith("/src/"):
            filename = filename[5:]
        results.append(
            {
                "test_id": finding.get("test_id"),
                "test_name": finding.get("test_name"),
                "issue_severity": finding.get("issue_severity"),
                "issue_confidence": finding.get("issue_confidence"),
                "issue_text": finding.get("issue_text"),
                "filename": filename,
                "line_number": finding.get("line_number"),
                "line_range": finding.get("line_range") or [],
                "more_info": finding.get("more_info"),
                "cwe": finding.get("issue_cwe") or {},
                "code": "[OMITTED]",
            }
        )
    sanitized = {
        "results": results,
        "errors": [
            {"filename": item.get("filename"), "reason": "[OMITTED]"}
            for item in (payload.get("errors", []) if isinstance(payload, dict) else [])
            if isinstance(item, dict)
        ],
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def write_trufflehog_output(raw_output: bytes, output_file: Path) -> None:
    sanitized = []
    for line in raw_output.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        filesystem = (((finding.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        path = str(filesystem.get("file") or "source")
        if path.startswith("/src/"):
            path = path[5:]
        sanitized.append(
            {
                "detector_name": finding.get("DetectorName"),
                "decoder_name": finding.get("DecoderName"),
                "verified": bool(finding.get("Verified")),
                "verification_attempted": False,
                "file": path,
                "line": filesystem.get("line"),
                "secret": "[REDACTED]",
            }
        )
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_trufflehog(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for finding in report if isinstance(report, list) else []:
            detector = str(finding.get("detector_name") or "Secret")[:200]
            decoder = str(finding.get("decoder_name") or "PLAIN")[:100]
            path = str(finding.get("file") or "source")[:2000]
            line = int(finding.get("line") or 0)
            asset = f"{path}:{line}" if line else path
            title = f"Potential {detector} secret detected"
            details = {
                "detector": detector,
                "decoder": decoder,
                "file": path,
                "line": line,
                "verified": False,
                "verification_attempted": False,
                "secret": "[REDACTED]",
            }
            fingerprint = hashlib.sha256(f"trufflehog|{detector}|{path}|{line}".encode()).hexdigest()
            records.append((uuid4(), run_id, "secret-detection", title, "high", asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_bandit(run_id: UUID, output_file: Path) -> int:
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for finding in report.get("results", []):
            test_id = str(finding.get("test_id") or "bandit-check")[:100]
            test_name = str(finding.get("test_name") or "python-security-check")[:200]
            title = str(finding.get("issue_text") or test_name)[:500]
            path = str(finding.get("filename") or "source")[:2000]
            line = int(finding.get("line_number") or 0)
            asset = f"{path}:{line}" if line else path
            raw_severity = str(finding.get("issue_severity") or "LOW").upper()
            cwe = finding.get("cwe") or {}
            details = {
                "finding": title,
                "test_id": test_id,
                "test_name": test_name,
                "file": path,
                "line": line,
                "line_range": finding.get("line_range") or [],
                "confidence": finding.get("issue_confidence"),
                "cwe_id": cwe.get("id") if isinstance(cwe, dict) else None,
                "cwe_link": cwe.get("link") if isinstance(cwe, dict) else None,
                "reference": finding.get("more_info"),
                "source_excerpt": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"bandit|{test_id}|{path}|{line}".encode()).hexdigest()
            records.append((uuid4(), run_id, "python-static-analysis", title, severity_map.get(raw_severity, "info"), asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_checkov(run_id: UUID, output_file: Path) -> int:
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for framework in report if isinstance(report, list) else [report]:
            check_type = str(framework.get("check_type") or "iac")[:100]
            for finding in (framework.get("results") or {}).get("failed_checks") or []:
                check_id = str(finding.get("check_id") or finding.get("bc_check_id") or "checkov-check")[:300]
                title = str(finding.get("check_name") or "Infrastructure-as-code issue")[:500]
                path = str(finding.get("file_path") or "source")[:2000]
                line_range = finding.get("file_line_range") or []
                start_line = int(line_range[0]) if line_range else 0
                asset = f"{path}:{start_line}" if start_line else path
                raw_severity = str(finding.get("severity") or "MEDIUM").upper()
                details = {
                    "finding": title,
                    "check_id": check_id,
                    "framework": check_type,
                    "resource": finding.get("resource"),
                    "file": path,
                    "start_line": start_line,
                    "end_line": int(line_range[-1]) if line_range else start_line,
                    "guideline": finding.get("guideline"),
                    "source_excerpt": "[OMITTED]",
                }
                fingerprint = hashlib.sha256(f"checkov|{check_type}|{check_id}|{path}|{finding.get('resource')}".encode()).hexdigest()
                records.append((uuid4(), run_id, "iac-misconfiguration", title, severity_map.get(raw_severity, "medium"), asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def capture_trivy_outputs(container, output_file: Path, sbom_file: Path) -> None:
    def read_container_json(container_path: str) -> dict:
        result = container.exec_run(["cat", container_path])
        if result.exit_code != 0:
            raise RuntimeError(f"Trivy output could not be read: {container_path}")
        payload = json.loads(result.output.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"Trivy output is not a JSON object: {container_path}")
        return payload

    raw = read_container_json("/tmp/trivy.json")
    sanitized_results = []
    for result in raw.get("Results", []):
        if not isinstance(result, dict):
            continue
        clean = {
            "Target": result.get("Target"),
            "Class": result.get("Class"),
            "Type": result.get("Type"),
        }
        vulnerabilities = []
        for item in result.get("Vulnerabilities") or []:
            vulnerabilities.append({key: item.get(key) for key in (
                "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion",
                "Severity", "Title", "PrimaryURL", "Status",
            )})
        misconfigurations = []
        for item in result.get("Misconfigurations") or []:
            misconfigurations.append({key: item.get(key) for key in (
                "ID", "Title", "Message", "Resolution", "Severity", "PrimaryURL",
            )})
        secrets = []
        for item in result.get("Secrets") or []:
            secrets.append({
                **{key: item.get(key) for key in (
                    "RuleID", "Category", "Title", "Severity", "StartLine", "EndLine",
                )},
                "Match": "[REDACTED]",
                "Secret": "[REDACTED]",
            })
        licenses = []
        for item in result.get("Licenses") or []:
            licenses.append({key: item.get(key) for key in (
                "Name", "Category", "Severity", "PkgName", "FilePath",
            )})
        if vulnerabilities:
            clean["Vulnerabilities"] = vulnerabilities
        if misconfigurations:
            clean["Misconfigurations"] = misconfigurations
        if secrets:
            clean["Secrets"] = secrets
        if licenses:
            clean["Licenses"] = licenses
        sanitized_results.append(clean)
    sanitized = {
        "SchemaVersion": raw.get("SchemaVersion"),
        "ArtifactName": "approved-source",
        "ArtifactType": raw.get("ArtifactType"),
        "Results": sanitized_results,
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")
    sbom = read_container_json("/tmp/sbom.cdx.json")
    sbom_file.write_text(json.dumps(sbom, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_trivy(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "UNKNOWN": "info",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for result in report.get("Results", []):
            target = str(result.get("Target") or "source")[:2000]
            for item in result.get("Vulnerabilities") or []:
                finding_id = str(item.get("VulnerabilityID") or "dependency-vulnerability")[:300]
                package = str(item.get("PkgName") or "package")[:500]
                details = {
                    "finding": item.get("Title") or f"{finding_id} affects {package}",
                    "vulnerability_id": finding_id,
                    "package": package,
                    "installed_version": item.get("InstalledVersion"),
                    "fixed_version": item.get("FixedVersion"),
                    "status": item.get("Status"),
                    "reference": item.get("PrimaryURL"),
                }
                fingerprint = hashlib.sha256(f"trivy|vuln|{finding_id}|{package}|{target}".encode()).hexdigest()
                records.append((uuid4(), run_id, "dependency-vulnerability", f"{finding_id}: {package}", severity_map.get(str(item.get("Severity") or "UNKNOWN").upper(), "info"), target, json.dumps(details), fingerprint))
            for item in result.get("Misconfigurations") or []:
                finding_id = str(item.get("ID") or "misconfiguration")[:300]
                title = str(item.get("Title") or "Configuration issue")[:500]
                details = {
                    "finding": item.get("Message") or title,
                    "check_id": finding_id,
                    "resolution": item.get("Resolution"),
                    "reference": item.get("PrimaryURL"),
                    "source_excerpt": "[OMITTED]",
                }
                fingerprint = hashlib.sha256(f"trivy|misconfig|{finding_id}|{target}".encode()).hexdigest()
                records.append((uuid4(), run_id, "configuration", title, severity_map.get(str(item.get("Severity") or "UNKNOWN").upper(), "info"), target, json.dumps(details), fingerprint))
            for item in result.get("Secrets") or []:
                finding_id = str(item.get("RuleID") or "secret")[:300]
                line = int(item.get("StartLine") or 0)
                asset = f"{target}:{line}" if line else target
                title = str(item.get("Title") or "Potential secret detected")[:500]
                details = {
                    "finding": title,
                    "rule_id": finding_id,
                    "category": item.get("Category"),
                    "start_line": line,
                    "end_line": int(item.get("EndLine") or line),
                    "secret": "[REDACTED]",
                    "match": "[REDACTED]",
                    "source_excerpt": "[OMITTED]",
                }
                fingerprint = hashlib.sha256(f"trivy|secret|{finding_id}|{target}|{line}".encode()).hexdigest()
                records.append((uuid4(), run_id, "secret-detection", title, severity_map.get(str(item.get("Severity") or "HIGH").upper(), "high"), asset, json.dumps(details), fingerprint))
            for item in result.get("Licenses") or []:
                name = str(item.get("Name") or "unknown-license")[:300]
                package = str(item.get("PkgName") or "package")[:500]
                asset = str(item.get("FilePath") or target)[:2000]
                details = {"finding": f"License {name} detected for {package}", "license": name, "category": item.get("Category"), "package": package}
                fingerprint = hashlib.sha256(f"trivy|license|{name}|{package}|{asset}".encode()).hexdigest()
                records.append((uuid4(), run_id, "license", f"License detected: {name}", severity_map.get(str(item.get("Severity") or "UNKNOWN").upper(), "info"), asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_testssl(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "OK": "info", "INFO": "info", "LOW": "low", "MEDIUM": "medium",
        "HIGH": "high", "CRITICAL": "critical", "WARN": "low",
    }
    records = []

    def checks(value, path=()):
        if isinstance(value, dict):
            if all(key in value for key in ("id", "severity", "finding")):
                yield path, value
                return
            for key, child in value.items():
                yield from checks(child, path + (str(key),))
        elif isinstance(value, list):
            for child in value:
                yield from checks(child, path)

    try:
        for raw_line in output_file.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            report = json.loads(raw_line)
            for target in report.get("scanResult", []):
                host = str(target.get("targetHost") or target.get("ip") or "TLS target")
                port = str(target.get("port") or "443")
                asset = f"{host}:{port}"[:2000]
                for path, item in checks(target):
                    check_id = str(item.get("id") or "tls-check")[:200]
                    category = next((part for part in path if part not in {"scanResult"}), "general")[:100]
                    finding = str(item.get("finding") or "TLS check result")[:4000]
                    raw_severity = str(item.get("severity") or "INFO").upper()
                    severity = severity_map.get(raw_severity, "info")
                    details = {
                        "category": category,
                        "finding": finding,
                        "testssl_severity": raw_severity,
                        "target_host": host,
                        "target_ip": target.get("ip"),
                        "port": port,
                    }
                    fingerprint = hashlib.sha256(f"testssl|{category}|{check_id}|{asset}".encode()).hexdigest()
                    records.append((uuid4(), run_id, "tls-check", f"TLS {category}: {check_id}", severity, asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_zap(run_id: UUID, output_file: Path) -> int:
    severity_map = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for site in report.get("site", []):
            asset = str(site.get("@name") or site.get("@host") or "HTTP target")[:2000]
            for alert in site.get("alerts", []):
                plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "zap-alert")[:200]
                title = str(alert.get("alert") or alert.get("name") or "ZAP passive alert")[:500]
                severity = severity_map.get(str(alert.get("riskcode") or "0"), "info")
                instances = [
                    {"uri": item.get("uri"), "method": item.get("method"), "param": item.get("param")}
                    for item in alert.get("instances", [])[:20]
                ]
                details = {
                    "plugin_id": plugin_id,
                    "risk": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"),
                    "description": alert.get("desc"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                    "cwe_id": alert.get("cweid"),
                    "wasc_id": alert.get("wascid"),
                    "instances": instances,
                }
                fingerprint = hashlib.sha256(f"zap|{plugin_id}|{asset}".encode()).hexdigest()
                records.append((uuid4(), run_id, "zap-passive", title, severity, asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity, asset = EXCLUDED.asset,
                    details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_semgrep(run_id: UUID, output_file: Path) -> int:
    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for finding in report.get("results", []):
            check_id = str(finding.get("check_id") or "semgrep-rule")[:300]
            path = str(finding.get("path") or "source")[:2000]
            start = finding.get("start") or {}
            end = finding.get("end") or {}
            line = int(start.get("line") or 0)
            asset = f"{path}:{line}" if line else path
            extra = finding.get("extra") or {}
            message = str(extra.get("message") or "Static analysis finding")[:1000]
            raw_severity = str(extra.get("severity") or "INFO").upper()
            metadata = extra.get("metadata") or {}
            details = {
                "check_id": check_id,
                "file": path,
                "start_line": line,
                "start_column": int(start.get("col") or 0),
                "end_line": int(end.get("line") or line),
                "end_column": int(end.get("col") or 0),
                "message": message,
                "semgrep_severity": raw_severity,
                "cwe": metadata.get("cwe"),
                "owasp": metadata.get("owasp"),
                "category": metadata.get("category"),
                "source_excerpt": "[OMITTED]",
                "metavariables": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(
                f"semgrep|{check_id}|{path}|{line}".encode()
            ).hexdigest()
            records.append(
                (
                    uuid4(), run_id, "static-analysis", message,
                    severity_map.get(raw_severity, "info"), asset,
                    json.dumps(details), fingerprint,
                )
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_gitleaks(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for finding in report if isinstance(report, list) else []:
            rule_id = str(finding.get("RuleID") or "secret")[:200]
            description = str(finding.get("Description") or "Potential secret detected")[:500]
            relative_file = str(finding.get("File") or "source")[:2000]
            start_line = int(finding.get("StartLine") or 0)
            asset = f"{relative_file}:{start_line}" if start_line else relative_file
            details = {
                "rule_id": rule_id,
                "file": relative_file,
                "start_line": start_line,
                "end_line": int(finding.get("EndLine") or start_line),
                "entropy": finding.get("Entropy"),
                "tags": finding.get("Tags") or [],
                "fingerprint": finding.get("Fingerprint"),
                "secret": "[REDACTED]",
                "match": "[REDACTED]",
            }
            fingerprint = hashlib.sha256(
                f"gitleaks|{rule_id}|{relative_file}|{start_line}".encode()
            ).hexdigest()
            records.append(
                (
                    uuid4(), run_id, "secret-detection", description, "high",
                    asset, json.dumps(details), fingerprint,
                )
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO observations
                    (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def execute_run(run_id: UUID) -> None:
    run = get_run(run_id)
    if run is None or run["status"] != "queued":
        return
    adapter = load_adapters().get(run["tool_id"])
    if adapter is None or adapter.get("profile") != run["profile"]:
        set_status(run_id, "failed", "Adapter policy mismatch")
        return
    if not run["authorization_confirmed"]:
        set_status(run_id, "failed", "Input authorization is not confirmed")
        return
    input_type = adapter.get("input", "target")
    if input_type == "source":
        if not run["source_artifact_id"]:
            set_status(run_id, "failed", "Source adapter has no approved source artifact")
            return
        source_container_path = SOURCE_ROOT / str(run["source_artifact_id"]) / "content"
        source_host_path = SOURCE_HOST_ROOT / str(run["source_artifact_id"]) / "content"
        if not source_container_path.is_dir():
            set_status(run_id, "failed", "Approved source artifact is missing from storage")
            return
    else:
        target_host = (urlsplit(run["base_url"]).hostname or "").lower().rstrip(".")
        allowed_hosts = {
            str(host).lower().rstrip(".") for host in (run["allowed_hosts"] or [])
        }
        if not target_host or target_host not in allowed_hosts:
            set_status(run_id, "failed", "Target host is not present in the saved allowed-host scope")
            return

    run_dir = EVIDENCE_ROOT / str(run_id)
    output_file = run_dir / "output.jsonl"
    event_file = run_dir / "events.jsonl"
    metadata_file = run_dir / "metadata.json"
    run_dir.mkdir(parents=True, exist_ok=True)

    metadata_file.write_text(
        json.dumps(
            {
                "run_id": str(run_id),
                "tool_id": run["tool_id"],
                "profile": run["profile"],
                "input_type": input_type,
                "target": run["base_url"] if input_type == "target" else None,
                "source_artifact_id": str(run["source_artifact_id"]) if run["source_artifact_id"] else None,
                "source_filename": run["source_filename"],
                "source_sha256": run["source_sha256"],
                "image": adapter["image"],
                "allowed_hosts": run["allowed_hosts"] if input_type == "target" else [],
                "excluded_paths": run["excluded_paths"] if input_type == "target" else [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    set_status(run_id, "running")
    append_event(event_file, {"event": "started", "time": time.time()})
    client = None
    container = None
    trivy_captured = False
    try:
        client = docker.from_env()
        resources = adapter.get("resources", {})
        memory = resources.get("memory", "512m")
        cpus = float(resources.get("cpus", 0.5))
        pids = int(resources.get("pids", 128))
        timeout_seconds = max(30, min(int(adapter.get("timeout_seconds", 600)), 7200))
        command = build_command(
            run["tool_id"], run["base_url"], adapter, run["excluded_paths"]
        )
        container = client.containers.run(
            adapter["image"],
            command=command,
            name=f"security-run-{run_id}",
            detach=True,
            # testssl and ZAP need ephemeral writable image layers for their own runtimes.
            # They remain non-root, capability-free, resource-limited, and are removed after each run.
            read_only=run["tool_id"] not in {"testssl", "wapiti", "zap-baseline", "zap-full"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=memory,
            nano_cpus=int(cpus * 1_000_000_000),
            pids_limit=pids,
            network_mode="none" if input_type == "source" else "bridge",
            user=adapter.get("user"),
            environment=(
                {
                    "HOME": "/tmp/semgrep-home",
                    "XDG_CACHE_HOME": "/tmp/semgrep-cache",
                    "SEMGREP_SETTINGS_FILE": "/tmp/semgrep-settings.yml",
                }
                if run["tool_id"] == "semgrep" else
                {"HOME": "/tmp/bandit-home"}
                if run["tool_id"] == "bandit" else
                {"HOME": "/tmp/checkov-home", "USER": "scanner"}
                if run["tool_id"] == "checkov" else
                {"HOME": "/tmp"}
                if run["tool_id"] == "trufflehog" else
                {"HOME": "/tmp/trivy-home", "XDG_CACHE_HOME": "/tmp/trivy-xdg"}
                if run["tool_id"] == "trivy" else None
            ),
            working_dir="/src" if input_type == "source" else "/tmp" if run["tool_id"] == "testssl" else "/zap/wrk" if run["tool_id"] in {"zap-baseline", "zap-full"} else None,
            entrypoint={"zap-baseline": "zap-baseline.py", "zap-full": "zap-full-scan.py", "trivy": "/bin/sh"}.get(run["tool_id"]),
            # testssl and ZAP reports must survive process exit long enough for docker cp.
            # Their writable container layers are ephemeral and removed in finally.
            tmpfs=(
                None if run["tool_id"] in {"testssl", "wapiti", "zap-baseline", "zap-full"}
                else {
                    "/tmp": "rw,nosuid,nodev,noexec,size=64m",
                    **(
                        {
                            "/root/.config": "rw,nosuid,nodev,noexec,size=16m",
                            "/root/.cache": "rw,nosuid,nodev,noexec,size=64m",
                        }
                        if run["tool_id"] in {"katana", "naabu", "nuclei-reviewed", "subfinder"}
                        else {}
                    ),
                    **(
                        {"/home/scanner/.config": "rw,nosuid,nodev,noexec,size=16m"}
                        if run["tool_id"] == "ffuf"
                        else {}
                    ),
                }
            ),
            labels={
                "security-platform.run-id": str(run_id),
                "security-platform.tool": run["tool_id"],
            },
            volumes=(
                {
                    str(source_host_path): {"bind": "/src", "mode": "ro"},
                    **(
                        {SEMGREP_RULES_HOST_PATH: {"bind": "/rules/semgrep-reviewed.yaml", "mode": "ro"}}
                        if run["tool_id"] == "semgrep" else {}
                    ),
                    **(
                        {TRIVY_CACHE_HOST_PATH: {"bind": "/cache", "mode": "ro"}}
                        if run["tool_id"] == "trivy" else {}
                    ),
                }
                if input_type == "source"
                else {NUCLEI_TEMPLATES_HOST_PATH: {"bind": "/templates", "mode": "ro"}}
                if run["tool_id"] == "nuclei-reviewed"
                else {FFUF_WORDLIST_HOST_PATH: {"bind": "/wordlists/content.txt", "mode": "ro"}}
                if run["tool_id"] == "ffuf"
                else {ARJUN_WORDLIST_HOST_PATH: {"bind": "/wordlists/parameters.txt", "mode": "ro"}}
                if run["tool_id"] == "arjun"
                else None
            ),
        )

        deadline = time.monotonic() + timeout_seconds
        while True:
            container.reload()
            current = get_run(run_id)
            if current and current["status"] in {"cancelling", "cancelled"}:
                container.stop(timeout=5)
                set_status(run_id, "cancelled")
                append_event(event_file, {"event": "cancelled", "time": time.time()})
                return
            if time.monotonic() >= deadline:
                container.stop(timeout=5)
                message = f"Tool exceeded configured timeout of {timeout_seconds} seconds"
                set_status(run_id, "failed", message)
                append_event(event_file, {"event": "timeout", "timeout_seconds": timeout_seconds, "time": time.time()})
                return
            if run["tool_id"] == "trivy" and container.status == "running":
                marker = container.exec_run(["test", "-f", "/tmp/.reports-ready"])
                if marker.exit_code == 0:
                    capture_trivy_outputs(container, output_file, run_dir / "sbom.cdx.json")
                    trivy_captured = True
                    container.stop(timeout=2)
                    break
            if container.status in {"exited", "dead"}:
                break
            time.sleep(POLL_SECONDS)

        result = container.wait(timeout=10)
        logs = container.logs(stdout=True, stderr=True)
        exit_code = 0 if trivy_captured else int(result.get("StatusCode", 1))
        if run["tool_id"] == "testssl":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code == 0:
                capture_testssl_output(container, output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] in {"zap-baseline", "zap-full"}:
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code in {0, 1, 2}:
                capture_json_output(container, "/zap/wrk/report.json", output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "wapiti":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code == 0:
                capture_json_output(container, "/tmp/report.json", output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "arjun":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code == 0:
                try:
                    capture_json_output(container, "/tmp/arjun.json", output_file)
                except (docker.errors.NotFound, RuntimeError):
                    output_file.write_text("{}\n", encoding="utf-8")
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "gitleaks":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code in {0, 1}:
                write_gitleaks_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "semgrep":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_semgrep_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "checkov":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_checkov_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "bandit":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_bandit_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "trufflehog":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_trufflehog_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text("[]\n", encoding="utf-8")
        elif run["tool_id"] == "trivy":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code != 0:
                output_file.write_bytes(logs)
        else:
            output_file.write_bytes(logs)
        successful_exit_codes = {0, 1, 2} if run["tool_id"] in {"zap-baseline", "zap-full"} else {0, 1} if run["tool_id"] == "gitleaks" else {0}
        if exit_code in successful_exit_codes:
            normalizers = {"arjun": normalize_arjun, "bandit": normalize_bandit, "checkov": normalize_checkov, "ffuf": normalize_ffuf, "gitleaks": normalize_gitleaks, "httpx": normalize_httpx, "katana": normalize_katana, "naabu": normalize_naabu, "nikto": normalize_nikto, "nmap": normalize_nmap, "nuclei-reviewed": normalize_nuclei, "semgrep": normalize_semgrep, "subfinder": normalize_subfinder, "testssl": normalize_testssl, "trivy": normalize_trivy, "trufflehog": normalize_trufflehog, "wapiti": normalize_wapiti, "zap-baseline": normalize_zap, "zap-full": normalize_zap}
            observation_count = normalizers[run["tool_id"]](run_id, output_file)
            set_status(run_id, "succeeded")
            append_event(event_file, {"event": "normalized", "observations": observation_count, "time": time.time()})
            append_event(event_file, {"event": "succeeded", "exit_code": exit_code, "time": time.time()})
        else:
            set_status(run_id, "failed", f"Tool exited with status {exit_code}")
            append_event(event_file, {"event": "failed", "exit_code": exit_code, "time": time.time()})
    except Exception as exc:
        set_status(run_id, "failed", str(exc)[:1000])
        append_event(event_file, {"event": "failed", "error": str(exc)[:1000], "time": time.time()})
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except docker.errors.DockerException:
                pass
        if client is not None:
            client.close()


def main() -> None:
    queue = redis.from_url(
        REDIS_URL,
        socket_connect_timeout=5,
        socket_timeout=10,
        decode_responses=True,
    )
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=heartbeat_loop, name="runner-heartbeat", daemon=True).start()
    while True:
        try:
            item = queue.blpop(RUN_QUEUE, timeout=5)
        except redis.TimeoutError:
            continue
        if item is None:
            continue
        try:
            execute_run(UUID(item[1]))
        except (ValueError, psycopg.Error, redis.RedisError) as exc:
            print(f"runner queue error: {exc}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
