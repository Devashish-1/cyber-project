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
import urllib.error
import urllib.request
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
EVIDENCE_HOST_ROOT = Path(os.getenv(
    "EVIDENCE_HOST_ROOT",
    "/home/killswitch/security-platform/evidence/runs",
))
SOURCE_ROOT = Path(os.getenv("SOURCE_ROOT", "/sources"))
SOURCE_HOST_ROOT = Path(os.getenv("SOURCE_HOST_ROOT", "/home/killswitch/security-platform/data/sources"))
TRIVY_CACHE_HOST_PATH = os.getenv(
    "TRIVY_CACHE_HOST_PATH",
    "/home/killswitch/security-platform/data/trivy-cache",
)
OSV_CACHE_HOST_PATH = os.getenv(
    "OSV_CACHE_HOST_PATH",
    "/home/killswitch/security-platform/data/osv-cache",
)
GRYPE_CACHE_HOST_PATH = os.getenv(
    "GRYPE_CACHE_HOST_PATH",
    "/home/killswitch/security-platform/data/grype-cache",
)
CODEQL_CACHE_HOST_PATH = os.getenv(
    "CODEQL_CACHE_HOST_PATH",
    "/home/killswitch/security-platform/data/codeql-cache",
)
KUBESCAPE_POLICY_HOST_PATH = os.getenv(
    "KUBESCAPE_POLICY_HOST_PATH",
    "/home/killswitch/security-platform/config/kubescape/nsa.json",
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
DNSRECON_WORDLIST_HOST_PATH = os.getenv(
    "DNSRECON_WORDLIST_HOST_PATH",
    "/home/killswitch/security-platform/config/wordlists/dns-reviewed-small.txt",
)
FFUF_WORDLIST_RUNNER_PATH = Path(
    os.getenv("FFUF_WORDLIST_RUNNER_PATH", "/app/config/wordlists/content-reviewed-small.txt")
)
ARJUN_WORDLIST_HOST_PATH = os.getenv(
    "ARJUN_WORDLIST_HOST_PATH",
    "/home/killswitch/security-platform/config/wordlists/parameters-reviewed-small.txt",
)
KITERUNNER_WORDLIST_RUNNER_PATH = Path(os.getenv(
    "KITERUNNER_WORDLIST_RUNNER_PATH",
    "/app/config/wordlists/api-routes-reviewed-small.txt",
))
RUN_QUEUE = "security-platform:runs"
RUNNER_HEARTBEAT = "security-platform:runner:heartbeat"
RUNNER_HEARTBEAT_TTL = 15
POLL_SECONDS = 1.0
MAX_API_SCHEMA_BYTES = 5 * 1024 * 1024


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


def seal_evidence(run_id: UUID, run_dir: Path) -> None:
    manifest_path = run_dir / "integrity.json"
    files = []
    for path in sorted(run_dir.iterdir(), key=lambda item: item.name):
        if path.name in {manifest_path.name, "integrity.json.tmp"} or path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        files.append({
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": digest.hexdigest(),
        })
    manifest = {
        "version": 1,
        "algorithm": "sha256",
        "run_id": str(run_id),
        "sealed_at": time.time(),
        "files": files,
    }
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = run_dir / "integrity.json.tmp"
    temporary.write_bytes(encoded)
    temporary.chmod(0o600)
    temporary.replace(manifest_path)
    manifest_digest = hashlib.sha256(encoded).hexdigest()
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE runs
                SET evidence_manifest_sha256 = %s, evidence_sealed_at = NOW()
                WHERE id = %s
                """,
                (manifest_digest, run_id),
            )


def get_run(run_id: UUID) -> dict | None:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.status, r.tool_id, r.profile, t.base_url, t.allowed_hosts,
                       t.excluded_paths, t.dns_resolver,
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
        "dns_resolver": row[6],
        "authorization_confirmed": row[7],
        "source_artifact_id": row[8],
        "source_filename": row[9],
        "source_sha256": row[10],
    }


def build_command(
    tool_id: str,
    base_url: str | None,
    adapter: dict | None = None,
    excluded_paths: list[str] | None = None,
    dns_resolver: str | None = None,
) -> list[str]:
    if tool_id == "codeql":
        return ["-c", "exit 64"]
    if tool_id == "playwright":
        return ["/input/browser-observe.js", "/input/browser-config.json"]
    if tool_id == "dnsx":
        if not dns_resolver:
            raise ValueError("dnsx requires an explicitly approved DNS resolver")
        return [
            "-l", "/input/hosts.txt",
            "-resolver", dns_resolver,
            "-a",
            "-resp",
            "-json",
            "-omit-raw",
            "-silent",
            "-retry", "1",
            "-threads", "1",
            "-rate-limit", "2",
            "-auth=false",
            "-disable-update-check",
            "-no-color",
        ]
    if tool_id == "kiterunner":
        return [
            "brute", base_url.rstrip("/"),
            "-w", "/wordlists/routes.txt",
            "-x", "2",
            "-j", "1",
            "--delay", "250ms",
            "--max-redirects", "0",
            "-d", "0",
            "--success-status-codes", "200,204,301,302,307,308,401,403,405",
            "-t", "5s",
            "--user-agent", "Security-Platform-Kiterunner/1.0",
            "--wildcard-detection=false",
            "--progress=false",
            "-o", "json",
            "-q",
        ]
    if tool_id == "sqlmap-controlled":
        target = urlsplit(base_url)
        if target.scheme not in {"http", "https"} or not target.netloc:
            raise ValueError("SQLmap target URL must be HTTP(S)")
        if not target.query:
            raise ValueError("Controlled SQLmap requires an authorized URL with a query parameter")
        return [
            "-u", base_url,
            "--batch",
            "--level", "1",
            "--risk", "1",
            "--technique", "BEU",
            "--threads", "1",
            "--delay", "0.5",
            "--timeout", "5",
            "--retries", "0",
            "--time-sec", "2",
            "--skip-waf",
            "--ignore-redirects",
            "--flush-session",
            "--output-dir", "/tmp/sqlmap",
            "--user-agent", "Security-Platform-SQLmap/1.0",
            "--disable-coloring",
        ]
    if tool_id == "schemathesis":
        target = urlsplit(base_url)
        if target.scheme not in {"http", "https"} or not target.netloc:
            raise ValueError("Schemathesis schema URL must be HTTP(S)")
        origin = f"{target.scheme}://{target.netloc}"
        command = [
            "run", "/schema/openapi.json",
            "--url", origin,
            "--phases", "fuzzing",
            "--workers", "1",
            "--max-time", "20",
            "--max-examples", "2",
            "--max-failures", "3",
            "--checks", "not_a_server_error,status_code_conformance,content_type_conformance,response_schema_conformance,negative_data_rejection",
            "--rate-limit", "2/s",
            "--request-timeout", "5",
            "--request-retries", "0",
            "--max-redirects", "0",
            "--generation-deterministic",
            "--output-sanitize", "true",
            "--output-truncate", "true",
            "--coverage-no-report",
            "--warnings", "off",
            "--no-color",
            "--report", "json",
            "--report-json-path", "/tmp/report.json",
        ]
        for path in excluded_paths or []:
            command.extend(["--exclude-path", "/" + str(path).lstrip("/")])
        return command
    if tool_id == "grype":
        return ["dir:/src", "-o", "json"]
    if tool_id == "syft":
        return ["scan", "dir:/src", "-o", "syft-json"]
    if tool_id == "osv-scanner":
        return [
            "scan", "source",
            "--offline",
            "--offline-vulnerabilities",
            "--recursive",
            "--format", "json",
            "--verbosity", "error",
            "/src",
        ]
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
    if tool_id == "kubescape":
        return [
            "scan", "framework", "nsa", "/src",
            "--use-from", "/policies/nsa.json",
            "--format", "json",
            "--scan-timeout", "90s",
            "--control-timeout", "5s",
        ]
    if tool_id == "massdns":
        return [
            "-r", "/input/resolvers.txt",
            "-t", "A",
            "-o", "J",
            "-q",
            "-c", "1",
            "-i", "1000",
            "--processes", "1",
            "--socket-count", "1",
            "/input/hosts.txt",
        ]
    if tool_id == "dnsrecon":
        if not dns_resolver:
            raise ValueError("dnsrecon requires an explicitly approved DNS resolver")
        if dns_resolver.startswith("["):
            resolver_match = re.fullmatch(r"\[([^]]+)]:(\d{1,5})", dns_resolver)
        else:
            resolver_match = re.fullmatch(r"([^:]+):(\d{1,5})", dns_resolver)
        if not resolver_match:
            raise ValueError("dnsrecon resolver must be a canonical IP address with port")
        resolver_ip, raw_port = resolver_match.groups()
        try:
            resolver_ip = str(ipaddress.ip_address(resolver_ip))
        except ValueError as exc:
            raise ValueError("dnsrecon resolver must be an IP address") from exc
        if int(raw_port) != 53:
            raise ValueError("dnsrecon supports approved DNS resolvers on port 53 only")
        host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
        return [
            "-d", host,
            "-n", resolver_ip,
            "-t", "brt",
            "-D", "/input/words.txt",
            "--threads", "1",
            "--lifetime", "2",
            "--disable_check_recursion",
            "--disable_check_bindversion",
            "--disable_recurs",
            "-j", "/output/raw.json",
            "--loglevel", "ERROR",
        ]
    if tool_id == "hadolint":
        return [
            "-c",
            "find /src -type f "
            "\\( -name Dockerfile -o -name '*.dockerfile' \\) "
            "-exec hadolint -f json {} +",
        ]
    if tool_id == "shellcheck":
        return ["-f", "json1", "/dev/null"]
    if tool_id == "njsscan":
        return ["--json", "/src"]
    if tool_id == "brakeman":
        return ["-p", "/src", "-f", "json", "--no-progress", "--no-threads", "--no-pager", "--no-color", "--force-scan"]
    if tool_id == "dalfox":
        return [
            "url", "--url", base_url,
            "--format", "json",
            "--workers", "1",
            "--rate-limit", "2",
            "--timeout", "30",
            "--silence",
            "--skip-mining",
            "--skip-mining-dict",
            "--skip-mining-dom",
            "--skip-waf-probe",
            "--only-poc", "v,r",
        ]
    if tool_id == "kics":
        return [
            "-c",
            "set +e; mkdir -p /tmp/kics-output; "
            "/app/bin/kics scan -p /src -o /tmp/kics-output --output-name results "
            "--report-formats json --no-progress --minimal-ui --parallel 1 "
            "--max-file-size 2 --timeout 20 --disable-full-descriptions "
            "--disable-secrets --ignore-on-exit results; code=$?; "
            "printf '%s' \"$code\" > /tmp/.kics-exit; "
            "touch /tmp/.reports-ready; while :; do sleep 1; done",
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
    if tool_id == "gobuster":
        candidates = [
            f"/{line.strip().lstrip('/')}"
            for line in FFUF_WORDLIST_RUNNER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for excluded in (excluded_paths or []):
            normalized = excluded.rstrip("/") or "/"
            if any(candidate == normalized or candidate.startswith(f"{normalized}/") for candidate in candidates):
                raise ValueError(f"Reviewed Gobuster wordlist intersects excluded path: {excluded}")
        return [
            "dir",
            "--url", base_url.rstrip("/") + "/",
            "--wordlist", "/wordlists/content.txt",
            "--threads", "2",
            "--delay", "250ms",
            "--timeout", "5s",
            "--status-codes", "200,204,301,302,307,308,401,403,405",
            "--status-codes-blacklist", "",
            "--useragent", "Security-Platform-Gobuster/1.0",
            "--quiet",
            "--no-progress",
            "--no-error",
            "--no-color",
        ]
    if tool_id == "feroxbuster":
        candidates = [
            f"/{line.strip().lstrip('/')}"
            for line in FFUF_WORDLIST_RUNNER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for excluded in (excluded_paths or []):
            normalized = excluded.rstrip("/") or "/"
            if any(candidate == normalized or candidate.startswith(f"{normalized}/") for candidate in candidates):
                raise ValueError(f"Reviewed Feroxbuster wordlist intersects excluded path: {excluded}")
        target = urlsplit(base_url)
        origin = f"{target.scheme}://{target.netloc}"
        command = [
            "--url", base_url.rstrip("/") + "/",
            "--wordlist", "/wordlists/content.txt",
            "--threads", "2",
            "--scan-limit", "1",
            "--rate-limit", "4",
            "--depth", "2",
            "--timeout", "5",
            "--time-limit", "90s",
            "--response-size-limit", "1048576",
            "--dont-extract-links",
            "--status-codes", "200", "204", "301", "302", "307", "308", "401", "403", "405",
            "--user-agent", "Security-Platform-Feroxbuster/1.0",
            "--json",
            "--silent",
            "--no-state",
            "--auto-bail",
        ]
        for excluded in excluded_paths or []:
            command.extend(["--dont-scan", origin + "/" + str(excluded).lstrip("/")])
        return command
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
    if tool_id == "zap-passive":
        scope_args = ["-c", "scope.conf", "--hook", "scope-hook.py"] if excluded_paths else []
        return [
            "-t", base_url,
            "-J", "report.json",
            *scope_args,
            "-m", "0",
            "-T", "3",
            "-I",
            "-s",
            "--autooff",
        ]
    if tool_id == "zap-baseline":
        scope_args = ["-c", "scope.conf", "--hook", "scope-hook.py"] if excluded_paths else []
        return [
            "-t", base_url,
            "-J", "report.json",
            *scope_args,
            "-m", "1",
            "-T", "5",
            "-I",
            "-s",
            "--autooff",
        ]
    if tool_id == "zap-full":
        scope_args = ["-c", "scope.conf", "--hook", "scope-hook.py"] if excluded_paths else []
        return [
            "-t", base_url,
            "-J", "report.json",
            *scope_args,
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


def normalize_dalfox(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "info",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("findings") or []:
            finding_type = str(finding.get("type") or "XSS")[:40]
            parameter = str(finding.get("param") or "unknown")[:300]
            method = str(finding.get("method") or "GET")[:20]
            location = str(finding.get("location") or "input")[:100]
            confidence = str(finding.get("confidence") or "unknown")[:40]
            title = f"Confirmed XSS in {location} parameter {parameter}"[:500]
            details = {
                "finding": finding.get("type_description") or title,
                "finding_type": finding_type,
                "parameter": parameter,
                "method": method,
                "location": location,
                "confidence": confidence,
                "confidence_reason": finding.get("confidence_reason"),
                "detection_method": finding.get("detection_method"),
                "injection_context": finding.get("inject_type"),
                "cwe": finding.get("cwe"),
                "message_id": finding.get("message_id"),
                "payload": "[OMITTED]",
                "evidence": "[OMITTED]",
                "proof_url": "[OMITTED]",
            }
            severity = severity_map.get(str(finding.get("severity") or "HIGH").upper(), "high")
            fingerprint = hashlib.sha256(
                f"dalfox|{finding_type}|{method}|{location}|{parameter}|{finding.get('message_id')}".encode()
            ).hexdigest()
            records.append((
                uuid4(), run_id, "cross-site-scripting", title, severity,
                f"{method} {location} parameter {parameter}", json.dumps(details), fingerprint,
            ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_sqlmap_output(raw_output: bytes, output_file: Path) -> None:
    text = raw_output.decode("utf-8", errors="replace")
    findings = []
    current = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.match(r"^Parameter:\s+(.+?)\s+\(([A-Z]+)\)$", line)
        if match:
            current = {
                "parameter": match.group(1)[:300],
                "method": match.group(2)[:20],
                "techniques": [],
            }
            findings.append(current)
            continue
        if current is None:
            continue
        if line.startswith("Type:"):
            technique = line.split(":", 1)[1].strip()[:200]
            if technique and technique not in current["techniques"]:
                current["techniques"].append(technique)
        elif line.startswith("Title:"):
            title = line.split(":", 1)[1].strip()[:300]
            if title:
                current.setdefault("titles", []).append(title)
    output_file.write_text(
        json.dumps(
            {
                "findings": findings,
                "summary": {
                    "injectable_parameters": len(findings),
                    "raw_console": "[OMITTED]",
                    "payloads": "[OMITTED]",
                },
            },
            separators=(",", ":"),
        ) + "\n",
        encoding="utf-8",
    )


def normalize_sqlmap(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("findings") or []:
            parameter = str(finding.get("parameter") or "unknown")[:300]
            method = str(finding.get("method") or "GET")[:20]
            techniques = [str(item)[:200] for item in finding.get("techniques") or []][:10]
            titles = [str(item)[:300] for item in finding.get("titles") or []][:10]
            title = f"SQL injection detected in {method} parameter {parameter}"[:500]
            details = {
                "finding": title,
                "parameter": parameter,
                "method": method,
                "techniques": techniques,
                "test_titles": titles,
                "payloads": "[OMITTED]",
                "raw_console": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(
                f"sqlmap|{method}|{parameter}|{'|'.join(techniques)}".encode()
            ).hexdigest()
            records.append((
                uuid4(), run_id, "sql-injection", title, "high",
                f"{method} parameter {parameter}", json.dumps(details), fingerprint,
            ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
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


def write_gobuster_output(raw_output: bytes, output_file: Path) -> None:
    findings = []
    pattern = re.compile(r"^/?(\S+)\s+\(Status:\s*(\d{3})\)\s*(?:\[Size:\s*(\d+)\])?")
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        match = pattern.match(raw_line.strip())
        if not match:
            continue
        findings.append({
            "path": ("/" + match.group(1).lstrip("/"))[:1000],
            "status": int(match.group(2)),
            "size": int(match.group(3)) if match.group(3) else None,
        })
        if len(findings) >= 1000:
            break
    output_file.write_text(
        json.dumps({"results": findings}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def normalize_gobuster(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            path = str(finding.get("path") or "/")[:1000]
            status = int(finding.get("status") or 0)
            size = finding.get("size")
            severity = "low" if status in {200, 204} else "info"
            title = f"HTTP content discovered: {path}"[:500]
            details = {
                "finding": title,
                "path": path,
                "status_code": status,
                "content_length": size,
            }
            fingerprint = hashlib.sha256(f"gobuster|{path}|{status}".encode()).hexdigest()
            records.append((uuid4(), run_id, "http-content", title, severity, path, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_feroxbuster_output(raw_output: bytes, output_file: Path) -> None:
    results = []
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if item.get("type") != "response":
            continue
        path = str(item.get("path") or "")
        if not path.startswith("/"):
            continue
        results.append({
            "path": path[:1000],
            "status": int(item.get("status") or 0),
            "method": str(item.get("method") or "GET")[:20],
            "content_length": int(item.get("content_length") or 0),
            "word_count": int(item.get("word_count") or 0),
            "line_count": int(item.get("line_count") or 0),
        })
        if len(results) >= 2000:
            break
    output_file.write_text(
        json.dumps({"results": results}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def normalize_feroxbuster(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        seen = set()
        for finding in report.get("results") or []:
            path = str(finding.get("path") or "/")[:1000]
            status = int(finding.get("status") or 0)
            method = str(finding.get("method") or "GET")[:20]
            key = (method, path, status)
            if key in seen:
                continue
            seen.add(key)
            severity = "low" if status in {200, 204} else "info"
            title = f"Nested HTTP content discovered: {path}"[:500]
            details = {
                "finding": title,
                "path": path,
                "method": method,
                "status_code": status,
                "content_length": finding.get("content_length"),
                "word_count": finding.get("word_count"),
                "line_count": finding.get("line_count"),
                "response_headers": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"feroxbuster|{method}|{path}|{status}".encode()).hexdigest()
            records.append((uuid4(), run_id, "recursive-http-content", title, severity, path, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_dnsx_output(raw_output: bytes, output_file: Path) -> None:
    results = []
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        host = str(item.get("host") or "").lower().rstrip(".")[:253]
        if not host:
            continue
        addresses = []
        for raw_address in (item.get("a") or [])[:32]:
            try:
                addresses.append(str(ipaddress.ip_address(str(raw_address))))
            except ValueError:
                continue
        results.append({
            "host": host,
            "record_type": "A",
            "addresses": sorted(set(addresses)),
            "status_code": str(item.get("status_code") or "")[:32],
            "ttl": int(item.get("ttl") or 0),
        })
        if len(results) >= 100:
            break
    output_file.write_text(
        json.dumps({"results": results}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def normalize_dnsx(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            host = str(finding.get("host") or "").lower().rstrip(".")[:253]
            addresses = finding.get("addresses") or []
            if not host or not isinstance(addresses, list):
                continue
            title = f"DNS A record observed: {host}"[:500]
            details = {
                "finding": title,
                "record_type": "A",
                "addresses": addresses[:32],
                "status_code": finding.get("status_code"),
                "ttl": finding.get("ttl"),
                "resolver": "[OMITTED]",
                "raw_response": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(
                f"dnsx|{host}|A|{','.join(sorted(addresses))}".encode()
            ).hexdigest()
            records.append((
                uuid4(), run_id, "dns-record", title, "info", host,
                json.dumps(details), fingerprint,
            ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_massdns_output(raw_output: bytes, output_file: Path) -> None:
    results = []
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        host = str(item.get("name") or "").lower().rstrip(".")[:253]
        if not host or str(item.get("type") or "").upper() != "A":
            continue
        addresses = []
        ttls = []
        for answer in ((item.get("data") or {}).get("answers") or [])[:32]:
            if not isinstance(answer, dict):
                continue
            if str(answer.get("type") or "").upper() != "A":
                continue
            try:
                addresses.append(str(ipaddress.ip_address(str(answer.get("data") or ""))))
            except ValueError:
                continue
            try:
                ttls.append(max(0, int(answer.get("ttl") or 0)))
            except (TypeError, ValueError):
                continue
        results.append({
            "host": host,
            "record_type": "A",
            "addresses": sorted(set(addresses)),
            "status": str(item.get("status") or "")[:32],
            "ttl": max(ttls or [0]),
        })
        if len(results) >= 10:
            break
    output_file.write_text(json.dumps({"results": results}, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_massdns(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            host = str(finding.get("host") or "").lower().rstrip(".")[:253]
            addresses = finding.get("addresses") or []
            if not host or not isinstance(addresses, list):
                continue
            title = f"MassDNS A record observed: {host}"[:500]
            details = {
                "finding": title,
                "record_type": "A",
                "addresses": addresses[:32],
                "status": finding.get("status"),
                "ttl": finding.get("ttl"),
                "resolver": "[OMITTED]",
                "raw_response": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"massdns|{host}|A|{','.join(sorted(addresses))}".encode()).hexdigest()
            records.append((uuid4(), run_id, "dns-record", title, "info", host, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_dnsrecon_output(raw_file: Path, output_file: Path) -> None:
    results = []
    try:
        report = json.loads(raw_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        report = []
    if not isinstance(report, list):
        report = []
    for item in report[:256]:
        if not isinstance(item, dict) or str(item.get("type") or "").upper() != "A":
            continue
        host = str(item.get("name") or "").lower().rstrip(".")[:253]
        try:
            address = str(ipaddress.ip_address(str(item.get("address") or "")))
        except ValueError:
            continue
        if not host or ":" in address:
            continue
        results.append({"host": host, "record_type": "A", "addresses": [address]})
        if len(results) >= 100:
            break
    output_file.write_text(json.dumps({"results": results}, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_dnsrecon(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            host = str(finding.get("host") or "").lower().rstrip(".")[:253]
            addresses = finding.get("addresses") or []
            if not host or not isinstance(addresses, list):
                continue
            addresses = sorted({str(ipaddress.ip_address(value)) for value in addresses})[:32]
            if not addresses:
                continue
            title = f"DNSRecon A record observed: {host}"[:500]
            details = {
                "finding": title,
                "record_type": "A",
                "addresses": addresses,
                "resolver": "[OMITTED]",
                "raw_response": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"dnsrecon|{host}|A|{','.join(addresses)}".encode()).hexdigest()
            records.append((uuid4(), run_id, "dns-record", title, "info", host, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_playwright_output(raw_output: bytes, output_file: Path) -> None:
    result = None
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("kind") == "browser-observation":
            result = {
                "kind": "browser-observation",
                "requested_url": str(item.get("requested_url") or "")[:2000],
                "final_url": str(item.get("final_url") or "")[:2000],
                "title": str(item.get("title") or "")[:500],
                "status_code": int(item.get("status_code") or 0),
                "content_type": str(item.get("content_type") or "")[:200],
                "same_origin_requests": min(max(int(item.get("same_origin_requests") or 0), 0), 10000),
                "blocked_requests": min(max(int(item.get("blocked_requests") or 0), 0), 10000),
                "failed_requests": min(max(int(item.get("failed_requests") or 0), 0), 10000),
                "console_errors": min(max(int(item.get("console_errors") or 0), 0), 10000),
                "page_errors": min(max(int(item.get("page_errors") or 0), 0), 10000),
            }
    output_file.write_text(
        json.dumps(result or {"kind": "browser-observation", "error": "sanitized browser result unavailable"}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def normalize_playwright(run_id: UUID, output_file: Path) -> int:
    try:
        item = json.loads(output_file.read_text(encoding="utf-8"))
        if item.get("error"):
            return 0
        asset = str(item.get("final_url") or item.get("requested_url") or "")[:2000]
        status = int(item.get("status_code") or 0)
        if not asset or not (100 <= status <= 599):
            return 0
        title = f"Browser page observed: HTTP {status}"[:500]
        details = {
            "finding": title,
            "title": item.get("title"),
            "status_code": status,
            "content_type": item.get("content_type"),
            "same_origin_requests": item.get("same_origin_requests"),
            "blocked_requests": item.get("blocked_requests"),
            "failed_requests": item.get("failed_requests"),
            "console_errors": item.get("console_errors"),
            "page_errors": item.get("page_errors"),
            "request_headers": "[OMITTED]",
            "response_headers": "[OMITTED]",
            "response_body": "[OMITTED]",
            "cookies": "[OMITTED]",
        }
        fingerprint = hashlib.sha256(f"playwright|{asset}|{status}".encode()).hexdigest()
        record = (uuid4(), run_id, "browser-page", title, "info", asset, json.dumps(details), fingerprint)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                record,
            )
    return 1


def codeql_languages(source_root: Path) -> list[str]:
    ignored = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build"}
    python_count = 0
    javascript_count = 0
    for path in source_root.rglob("*"):
        if not path.is_file() or any(part in ignored for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            python_count += 1
        elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            javascript_count += 1
    languages = []
    if python_count:
        languages.append("python")
    if javascript_count:
        languages.append("javascript")
    if not languages:
        raise ValueError("CodeQL currently requires authorized Python or JavaScript/TypeScript source")
    return languages


def build_codeql_command(languages: list[str]) -> list[str]:
    suites = {
        "python": "/opt/codeql-repo/python/ql/src/codeql-suites/python-security-and-quality.qls",
        "javascript": "/opt/codeql-repo/javascript/ql/src/codeql-suites/javascript-security-and-quality.qls",
    }
    commands = ["set -eu"]
    for language in languages:
        database = f"/tmp/db-{language}"
        report = f"/tmp/{language}.sarif"
        commands.append(
            f"codeql database create {database} --language={language} --build-mode=none "
            "--source-root=/src --threads=1 --overwrite"
        )
        commands.append(
            f"codeql database analyze {database} {suites[language]} "
            f"--format=sarif-latest --output={report} --threads=1 --ram=3072 "
            "--no-sarif-add-file-contents --no-sarif-add-snippets "
            "--sarif-include-query-help=never"
        )
        commands.append(f"cat {report}")
    return ["-c", "; ".join(commands)]


def write_codeql_output(raw_output: bytes, output_file: Path) -> None:
    text = raw_output.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder()
    position = 0
    findings = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        try:
            report, position = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            break
        for sarif_run in report.get("runs") or []:
            rules = {}
            driver = ((sarif_run.get("tool") or {}).get("driver") or {})
            for rule in driver.get("rules") or []:
                rule_id = str(rule.get("id") or "")[:200]
                if rule_id:
                    rules[rule_id] = rule
            for result in sarif_run.get("results") or []:
                if len(findings) >= 2000:
                    break
                rule_id = str(result.get("ruleId") or "")[:200]
                location = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
                artifact = location.get("artifactLocation") or {}
                raw_uri = str(artifact.get("uri") or "")
                parsed_uri = urlsplit(raw_uri)
                path = parsed_uri.path if parsed_uri.scheme == "file" else raw_uri
                path = path.replace("\\", "/")
                if path.startswith("/src/"):
                    path = path[5:]
                path = path.lstrip("/")[:1000]
                region = location.get("region") or {}
                line = max(int(region.get("startLine") or 1), 1)
                message = str((result.get("message") or {}).get("text") or "CodeQL finding")[:1000]
                rule = rules.get(rule_id) or {}
                properties = rule.get("properties") or {}
                try:
                    score = float(properties.get("security-severity") or 0)
                except (TypeError, ValueError):
                    score = 0
                severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                findings.append({
                    "rule_id": rule_id,
                    "message": message,
                    "severity": severity,
                    "security_score": score,
                    "path": path,
                    "line": line,
                    "tags": [str(tag)[:200] for tag in (properties.get("tags") or [])[:20]],
                })
    output_file.write_text(json.dumps({"results": findings}, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_codeql(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            rule_id = str(finding.get("rule_id") or "codeql")[:200]
            path = str(finding.get("path") or "unknown")[:1000]
            line = max(int(finding.get("line") or 1), 1)
            severity = str(finding.get("severity") or "low")
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "low"
            title = f"CodeQL {rule_id}"[:500]
            asset = f"{path}:{line}"[:2000]
            details = {
                "finding": str(finding.get("message") or title)[:1000],
                "rule_id": rule_id,
                "path": path,
                "line": line,
                "security_score": finding.get("security_score"),
                "tags": finding.get("tags") or [],
                "source_snippet": "[OMITTED]",
                "code_flow": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"codeql|{rule_id}|{path}|{line}".encode()).hexdigest()
            records.append((uuid4(), run_id, "codeql-finding", title, severity, asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def write_kiterunner_output(raw_output: bytes, output_file: Path) -> None:
    results = []
    for raw_line in raw_output.decode("utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        method = str(item.get("method") or "")[:20]
        path = str(item.get("path") or "")[:1000]
        responses = item.get("responses")
        if not method or not path.startswith("/") or not isinstance(responses, list):
            continue
        for response in responses[:5]:
            if not isinstance(response, dict):
                continue
            results.append({
                "method": method,
                "path": path,
                "status": int(response.get("sc") or 0),
                "content_length": int(response.get("len") or 0),
            })
            if len(results) >= 1000:
                break
        if len(results) >= 1000:
            break
    output_file.write_text(
        json.dumps({"results": results}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def normalize_kiterunner(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        seen = set()
        for finding in report.get("results") or []:
            method = str(finding.get("method") or "GET")[:20]
            path = str(finding.get("path") or "")[:1000]
            status = int(finding.get("status") or 0)
            key = (method, path, status)
            if not path.startswith("/") or key in seen:
                continue
            seen.add(key)
            severity = "low" if status in {200, 204} else "info"
            title = f"API route discovered: {method} {path}"[:500]
            details = {
                "finding": title,
                "method": method,
                "path": path,
                "status_code": status,
                "content_length": finding.get("content_length"),
                "request_headers": "[OMITTED]",
                "response_headers": "[OMITTED]",
                "response_body": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(
                f"kiterunner|{method}|{path}|{status}".encode()
            ).hexdigest()
            records.append((
                uuid4(), run_id, "api-route", title, severity, path,
                json.dumps(details), fingerprint,
            ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
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


def capture_kics_output(container, output_file: Path) -> None:
    result = container.exec_run(["cat", "/tmp/kics-output/results.json"])
    if result.exit_code != 0:
        raise RuntimeError("KICS JSON output could not be read")
    payload = json.loads(result.output.decode("utf-8"))
    for query in payload.get("queries", []) if isinstance(payload, dict) else []:
        for finding in query.get("files", []) if isinstance(query, dict) else []:
            if not isinstance(finding, dict):
                continue
            for key in ("actual_value", "search_key", "search_value"):
                if key in finding:
                    finding[key] = "[OMITTED]"
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


def write_schemathesis_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Schemathesis report is not a JSON object")
    failures = []
    for finding in (payload.get("failures") or [])[:200]:
        if not isinstance(finding, dict):
            continue
        failures.append({
            "type": finding.get("type"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "count": finding.get("count"),
            "operations": [str(item)[:500] for item in (finding.get("operations") or [])[:100]],
        })
    errors = []
    for error in (payload.get("errors") or [])[:100]:
        if not isinstance(error, dict):
            continue
        errors.append({
            "type": error.get("type"),
            "title": error.get("title"),
        })
    sanitized = {
        "schema": "security-platform-schemathesis-v1",
        "schemathesis_version": payload.get("schemathesis_version"),
        "running_time": payload.get("running_time"),
        "stop_reason": payload.get("stop_reason"),
        "complete": payload.get("complete"),
        "exit_code": payload.get("exit_code"),
        "operations": payload.get("operations"),
        "phases": payload.get("phases"),
        "test_cases": payload.get("test_cases"),
        "failure_count": len(failures),
        "failures": failures,
        "error_count": len(errors),
        "errors": errors,
        "requests": "[OMITTED]",
        "responses": "[OMITTED]",
        "payloads": "[OMITTED]",
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_schemathesis(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "info",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for failure in report.get("failures") or []:
            finding_type = str(failure.get("type") or "api-conformance")[:300]
            title = str(failure.get("title") or "API contract violation")[:500]
            severity = severity_map.get(str(failure.get("severity") or "MEDIUM").upper(), "medium")
            operations = failure.get("operations") or ["API operation"]
            for operation in operations[:100]:
                asset = str(operation or "API operation")[:2000]
                details = {
                    "finding": title,
                    "failure_type": finding_type,
                    "operation": asset,
                    "occurrences": int(failure.get("count") or 1),
                    "requests": "[OMITTED]",
                    "responses": "[OMITTED]",
                    "payloads": "[OMITTED]",
                }
                fingerprint = hashlib.sha256(f"schemathesis|{finding_type}|{asset}".encode()).hexdigest()
                records.append((uuid4(), run_id, "api-contract-violation", title, severity, asset, json.dumps(details), fingerprint))
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


def write_grype_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Grype output is not a JSON object")
    matches = []
    for match in (payload.get("matches") or [])[:5000]:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vulnerability.get("fix") or {}
        locations = []
        for location in (artifact.get("locations") or [])[:20]:
            if isinstance(location, dict) and location.get("path"):
                locations.append({"path": str(location.get("path"))[:2000]})
        details = []
        for item in (match.get("matchDetails") or [])[:20]:
            if not isinstance(item, dict):
                continue
            found = item.get("found") or {}
            item_fix = item.get("fix") or {}
            details.append({
                "type": item.get("type"),
                "matcher": item.get("matcher"),
                "vulnerability_id": found.get("vulnerabilityID"),
                "version_constraint": found.get("versionConstraint"),
                "suggested_version": item_fix.get("suggestedVersion"),
            })
        matches.append({
            "vulnerability": {
                "id": vulnerability.get("id"),
                "namespace": vulnerability.get("namespace"),
                "severity": vulnerability.get("severity"),
                "urls": (vulnerability.get("urls") or [])[:20],
                "fix": {
                    "versions": (fix.get("versions") or [])[:20],
                    "state": fix.get("state"),
                },
                "risk": vulnerability.get("risk"),
            },
            "artifact": {
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "type": artifact.get("type"),
                "purl": artifact.get("purl"),
                "language": artifact.get("language"),
                "locations": locations,
            },
            "match_details": details,
        })
    sanitized = {
        "schema": "security-platform-grype-v1",
        "source": {"type": "approved-source"},
        "match_count": len(matches),
        "matches_truncated": len(payload.get("matches") or []) > len(matches),
        "matches": matches,
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_grype(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "NEGLIGIBLE": "info", "UNKNOWN": "info",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for match in report.get("matches") or []:
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            vulnerability_id = str(vulnerability.get("id") or "dependency-vulnerability")[:300]
            name = str(artifact.get("name") or "package")[:500]
            version = str(artifact.get("version") or "unknown")[:300]
            package_type = str(artifact.get("type") or "unknown")[:100]
            purl = str(artifact.get("purl") or "")[:2000]
            fix = vulnerability.get("fix") or {}
            locations = [
                str(location.get("path") or "")[:2000]
                for location in (artifact.get("locations") or [])[:20]
                if isinstance(location, dict) and location.get("path")
            ]
            details = {
                "finding": f"{vulnerability_id} affects {name} {version}",
                "vulnerability_id": vulnerability_id,
                "namespace": vulnerability.get("namespace"),
                "package": name,
                "installed_version": version,
                "package_type": package_type,
                "purl": purl or None,
                "fixed_versions": (fix.get("versions") or [])[:20],
                "fix_state": fix.get("state"),
                "references": (vulnerability.get("urls") or [])[:20],
                "risk": vulnerability.get("risk"),
                "locations": locations,
                "match_details": (match.get("match_details") or [])[:20],
                "source_content": "[OMITTED]",
            }
            asset = purl or f"{package_type}:{name}@{version}"
            fingerprint = hashlib.sha256(f"grype|{vulnerability_id}|{package_type}|{name}|{version}|{purl}".encode()).hexdigest()
            severity = severity_map.get(str(vulnerability.get("severity") or "UNKNOWN").upper(), "info")
            records.append((uuid4(), run_id, "dependency-vulnerability", f"{vulnerability_id}: {name} {version}", severity, asset, json.dumps(details), fingerprint))
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


def write_syft_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Syft output is not a JSON object")
    artifacts = []
    for artifact in (payload.get("artifacts") or [])[:5000]:
        if not isinstance(artifact, dict):
            continue
        locations = []
        for location in (artifact.get("locations") or [])[:20]:
            if not isinstance(location, dict):
                continue
            path = str(location.get("path") or location.get("accessPath") or "")
            if path:
                locations.append({"path": path[:2000]})
        artifacts.append({
            "name": artifact.get("name"),
            "version": artifact.get("version"),
            "type": artifact.get("type"),
            "purl": artifact.get("purl"),
            "cpes": (artifact.get("cpes") or [])[:20],
            "licenses": (artifact.get("licenses") or [])[:20],
            "language": artifact.get("language"),
            "locations": locations,
        })
    sanitized = {
        "schema": {"version": (payload.get("schema") or {}).get("version")},
        "source": {"type": "approved-source"},
        "artifact_count": len(artifacts),
        "artifacts_truncated": len(payload.get("artifacts") or []) > len(artifacts),
        "artifacts": artifacts,
    }
    output_file.write_text(json.dumps(sanitized, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_syft(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for artifact in report.get("artifacts") or []:
            name = str(artifact.get("name") or "unnamed-component")[:500]
            version = str(artifact.get("version") or "unknown")[:300]
            package_type = str(artifact.get("type") or "unknown")[:100]
            purl = str(artifact.get("purl") or "")[:2000]
            locations = [
                str(location.get("path") or "")[:2000]
                for location in (artifact.get("locations") or [])[:20]
                if isinstance(location, dict) and location.get("path")
            ]
            asset = purl or f"{package_type}:{name}@{version}"
            details = {
                "finding": f"Software component {name} {version} detected",
                "component": name,
                "version": version,
                "package_type": package_type,
                "purl": purl or None,
                "cpes": (artifact.get("cpes") or [])[:20],
                "licenses": (artifact.get("licenses") or [])[:20],
                "language": artifact.get("language"),
                "locations": locations,
                "source_content": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"syft|{package_type}|{name}|{version}|{purl}".encode()).hexdigest()
            records.append((uuid4(), run_id, "software-component", f"Component detected: {name} {version}", "info", asset, json.dumps(details), fingerprint))
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


def write_dalfox_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    sanitized_findings = []
    for finding in payload.get("findings", []) if isinstance(payload, dict) else []:
        if not isinstance(finding, dict):
            continue
        sanitized_findings.append({
            "confidence": finding.get("confidence"),
            "confidence_reason": finding.get("confidence_reason"),
            "cwe": finding.get("cwe"),
            "detection_method": finding.get("detection_method"),
            "inject_type": finding.get("inject_type"),
            "location": finding.get("location"),
            "message_id": finding.get("message_id"),
            "method": finding.get("method"),
            "param": finding.get("param"),
            "severity": finding.get("severity"),
            "type": finding.get("type"),
            "type_description": finding.get("type_description"),
            "data": "[OMITTED]",
            "evidence": "[OMITTED]",
            "message_str": "[OMITTED]",
            "payload": "[OMITTED]",
        })
    meta = payload.get("meta") or {} if isinstance(payload, dict) else {}
    sanitized_meta = {
        key: meta.get(key)
        for key in (
            "dalfox_version", "dedup_mode", "failed_requests", "findings_count",
            "incomplete", "scan_duration_ms", "targets_deduplicated", "total_requests",
        )
    }
    output_file.write_text(
        json.dumps({"findings": sanitized_findings, "meta": sanitized_meta}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


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


def write_osv_output(raw_output: bytes, output_file: Path) -> None:
    payload = json.loads(raw_output.decode("utf-8"))
    results = []
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        source = result.get("source") or {}
        path = str(source.get("path") or "source")
        if path.startswith("/src/"):
            path = path[5:]
        packages = []
        for item in result.get("packages") or []:
            package = item.get("package") or {}
            groups = []
            for group in item.get("groups") or []:
                groups.append(
                    {
                        "ids": group.get("ids") or [],
                        "aliases": group.get("aliases") or [],
                        "max_severity": group.get("max_severity"),
                    }
                )
            packages.append({"package": package, "groups": groups})
        results.append({"source": {"path": path, "type": source.get("type")}, "packages": packages})
    output_file.write_text(json.dumps({"results": results}, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_osv(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
        for result in report.get("results", []):
            path = str((result.get("source") or {}).get("path") or "source")[:2000]
            for item in result.get("packages") or []:
                package = item.get("package") or {}
                name = str(package.get("name") or "package")[:300]
                version = str(package.get("version") or "unknown")[:200]
                ecosystem = str(package.get("ecosystem") or "unknown")[:100]
                for group in item.get("groups") or []:
                    ids = [str(value)[:200] for value in (group.get("ids") or [])]
                    aliases = [str(value)[:200] for value in (group.get("aliases") or [])]
                    advisory = ids[0] if ids else (aliases[0] if aliases else "OSV advisory")
                    try:
                        score = float(group.get("max_severity") or 0)
                    except (TypeError, ValueError):
                        score = 0.0
                    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                    title = f"{advisory} affects {name} {version}"
                    details = {"advisory_ids": ids, "aliases": aliases, "package": name, "version": version, "ecosystem": ecosystem, "max_cvss": score, "manifest": path}
                    fingerprint = hashlib.sha256(f"osv|{ecosystem}|{name}|{version}|{advisory}|{path}".encode()).hexdigest()
                    records.append((uuid4(), run_id, "dependency-vulnerability", title, severity, f"{path}:{name}@{version}", json.dumps(details), fingerprint))
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


def write_kubescape_output(raw_output: bytes, output_file: Path) -> None:
    findings = []
    try:
        report = json.loads(raw_output.decode("utf-8", errors="replace"))
        seen = set()
        for resource in report.get("results") or []:
            resource_id = str(resource.get("resourceID") or "kubernetes-resource")[:1000]
            for control in resource.get("controls") or []:
                status = str((control.get("status") or {}).get("status") or "").lower()
                if status != "failed":
                    continue
                control_id = str(control.get("controlID") or "kubescape")[:100]
                key = (control_id, resource_id)
                if key in seen:
                    continue
                seen.add(key)
                severity = str(control.get("severity") or "medium").lower()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "medium"
                findings.append({
                    "control_id": control_id,
                    "name": str(control.get("name") or "Kubernetes control failed")[:500],
                    "severity": severity,
                    "resource": resource_id,
                    "failed_rules": [
                        str(rule.get("name") or "")[:200]
                        for rule in (control.get("rules") or [])
                        if str((rule.get("status") or "")).lower() == "failed"
                    ][:20],
                })
                if len(findings) >= 2000:
                    break
            if len(findings) >= 2000:
                break
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        findings = []
    output_file.write_text(json.dumps({"results": findings}, separators=(",", ":")) + "\n", encoding="utf-8")


def normalize_kubescape(run_id: UUID, output_file: Path) -> int:
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for finding in report.get("results") or []:
            control_id = str(finding.get("control_id") or "kubescape")[:100]
            resource = str(finding.get("resource") or "kubernetes-resource")[:1000]
            severity = str(finding.get("severity") or "medium")
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "medium"
            title = f"{control_id}: {str(finding.get('name') or 'Kubernetes control failed')[:380]}"[:500]
            details = {
                "finding": title,
                "control_id": control_id,
                "resource": resource,
                "failed_rules": finding.get("failed_rules") or [],
                "resource_manifest": "[OMITTED]",
                "fix_paths": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(f"kubescape|{control_id}|{resource}".encode()).hexdigest()
            records.append((uuid4(), run_id, "kubernetes-misconfiguration", title, severity, resource, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
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


def normalize_kics(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "TRACE": "info",
    }
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        for query in report.get("queries") or []:
            query_id = str(query.get("query_id") or "kics-query")[:200]
            title = str(query.get("query_name") or "Infrastructure-as-code issue")[:500]
            severity = severity_map.get(str(query.get("severity") or "INFO").upper(), "info")
            for finding in query.get("files") or []:
                raw_path = str(finding.get("file_name") or "source").replace("\\", "/")
                path = raw_path
                for prefix in ("../../src/", "../src/", "/src/"):
                    if path.startswith(prefix):
                        path = path[len(prefix):]
                        break
                path = path.lstrip("/") or "source"
                line = int(finding.get("line") or finding.get("search_line") or 0)
                asset = f"{path}:{line}" if line else path
                details = {
                    "finding": str(query.get("description") or title)[:2000],
                    "query_id": query_id,
                    "platform": query.get("platform"),
                    "cwe": query.get("cwe"),
                    "risk_score": query.get("risk_score"),
                    "cloud_provider": query.get("cloud_provider"),
                    "category": query.get("category"),
                    "resource_type": finding.get("resource_type"),
                    "resource_name": finding.get("resource_name"),
                    "issue_type": finding.get("issue_type"),
                    "file": path,
                    "line": line,
                    "expected_value": finding.get("expected_value"),
                    "reference": query.get("query_url"),
                    "actual_value": "[OMITTED]",
                    "search_key": "[OMITTED]",
                    "search_value": "[OMITTED]",
                    "source_excerpt": "[OMITTED]",
                }
                similarity = str(finding.get("similarity_id") or "")
                fingerprint = hashlib.sha256(
                    f"kics|{query_id}|{similarity}|{path}|{line}".encode()
                ).hexdigest()
                records.append((
                    uuid4(), run_id, "iac-misconfiguration", title, severity,
                    asset, json.dumps(details), fingerprint,
                ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id,run_id,observation_type,title,severity,asset,details,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id,fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def normalize_hadolint(run_id: UUID, output_file: Path) -> int:
    severity_map = {
        "error": "high",
        "warning": "medium",
        "info": "low",
        "style": "info",
        "ignore": "info",
    }
    records = []
    try:
        raw = output_file.read_text(encoding="utf-8")
        batches = []
        decoder = json.JSONDecoder()
        offset = 0
        while offset < len(raw):
            while offset < len(raw) and raw[offset].isspace():
                offset += 1
            if offset >= len(raw):
                break
            payload, offset = decoder.raw_decode(raw, offset)
            if isinstance(payload, list):
                batches.extend(payload)
        for finding in batches:
            rule_id = str(finding.get("code") or "hadolint-rule")[:100]
            path = str(finding.get("file") or "Dockerfile")[:2000]
            line = int(finding.get("line") or 0)
            column = int(finding.get("column") or 0)
            level = str(finding.get("level") or "warning").lower()
            message = str(finding.get("message") or "Dockerfile lint issue")[:500]
            asset = f"{path}:{line}" if line else path
            details = {
                "finding": message,
                "rule_id": rule_id,
                "file": path,
                "line": line,
                "column": column,
                "level": level,
                "reference": f"https://github.com/hadolint/hadolint/wiki/{rule_id}",
                "source_excerpt": "[OMITTED]",
            }
            fingerprint = hashlib.sha256(
                f"hadolint|{rule_id}|{path}|{line}|{column}".encode()
            ).hexdigest()
            records.append((
                uuid4(), run_id, "dockerfile-lint", f"{rule_id}: {message}",
                severity_map.get(level, "info"), asset, json.dumps(details), fingerprint,
            ))
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
                    title = EXCLUDED.title, severity = EXCLUDED.severity,
                    asset = EXCLUDED.asset, details = EXCLUDED.details
                """,
                records,
            )
    return len(records)


def normalize_shellcheck(run_id: UUID, output_file: Path) -> int:
    severity_map = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
    records = []
    try:
        raw, decoder, offset, findings = output_file.read_text(encoding="utf-8"), json.JSONDecoder(), 0, []
        while offset < len(raw):
            while offset < len(raw) and raw[offset].isspace():
                offset += 1
            if offset >= len(raw):
                break
            payload, offset = decoder.raw_decode(raw, offset)
            if isinstance(payload, dict):
                findings.extend(payload.get("comments") or [])
        for item in findings:
            code = f"SC{int(item.get('code') or 0):04d}"
            path = str(item.get("file") or "script.sh")[:2000]
            line, column = int(item.get("line") or 0), int(item.get("column") or 0)
            level = str(item.get("level") or "info").lower()
            message = str(item.get("message") or "Shell issue")[:500]
            details = {"finding": message, "rule_id": code, "file": path, "line": line, "column": column, "reference": f"https://www.shellcheck.net/wiki/{code}", "source_excerpt": "[OMITTED]"}
            fingerprint = hashlib.sha256(f"shellcheck|{code}|{path}|{line}|{column}".encode()).hexdigest()
            records.append((uuid4(), run_id, "shell-static-analysis", f"{code}: {message}", severity_map.get(level, "info"), f"{path}:{line}", json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def normalize_njsscan(run_id: UUID, output_file: Path) -> int:
    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        if report.get("errors"):
            raise RuntimeError("njsscan reported an internal analysis error")
        for category in ("nodejs", "templates"):
            for rule_id, rule in (report.get(category) or {}).items():
                metadata = rule.get("metadata") or {}
                title = str(metadata.get("description") or rule_id)[:500]
                severity = severity_map.get(str(metadata.get("severity") or "INFO").upper(), "info")
                for finding in rule.get("files") or []:
                    path = str(finding.get("file_path") or "source")[:2000]
                    lines = finding.get("match_lines") or []
                    start_line = int(lines[0]) if lines else 0
                    asset = f"{path}:{start_line}" if start_line else path
                    details = {
                        "finding": title,
                        "rule_id": str(rule_id)[:200],
                        "category": category,
                        "file": path,
                        "start_line": start_line,
                        "end_line": int(lines[-1]) if lines else start_line,
                        "cwe": metadata.get("cwe"),
                        "owasp": metadata.get("owasp-web"),
                        "source_excerpt": "[OMITTED]",
                    }
                    fingerprint = hashlib.sha256(f"njsscan|{category}|{rule_id}|{path}|{start_line}".encode()).hexdigest()
                    records.append((uuid4(), run_id, "javascript-static-analysis", title, severity, asset, json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """INSERT INTO observations
                (id, run_id, observation_type, title, severity, asset, details, fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                ON CONFLICT (run_id, fingerprint) DO UPDATE SET
                title=EXCLUDED.title,severity=EXCLUDED.severity,
                asset=EXCLUDED.asset,details=EXCLUDED.details""",
                records,
            )
    return len(records)


def normalize_brakeman(run_id: UUID, output_file: Path) -> int:
    confidence_map = {"High": "high", "Medium": "medium", "Weak": "low"}
    records = []
    try:
        report = json.loads(output_file.read_text(encoding="utf-8"))
        if report.get("errors"):
            raise RuntimeError("Brakeman reported an internal analysis error")
        for item in report.get("warnings") or []:
            check = str(item.get("check_name") or "brakeman")[:100]
            warning_type = str(item.get("warning_type") or "Ruby security issue")[:200]
            message = str(item.get("message") or warning_type)[:500]
            path, line = str(item.get("file") or "source")[:2000], int(item.get("line") or 0)
            details = {"finding": message, "check": check, "warning_type": warning_type, "file": path, "line": line, "confidence": item.get("confidence"), "cwe_ids": item.get("cwe_id") or [], "reference": item.get("link"), "source_excerpt": "[OMITTED]", "user_input": "[OMITTED]"}
            fingerprint = str(item.get("fingerprint") or hashlib.sha256(f"brakeman|{check}|{path}|{line}".encode()).hexdigest())[:128]
            records.append((uuid4(), run_id, "ruby-static-analysis", f"{warning_type}: {message}", confidence_map.get(str(item.get("confidence")), "medium"), f"{path}:{line}", json.dumps(details), fingerprint))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return 0
    if not records:
        return 0
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.executemany("""INSERT INTO observations (id,run_id,observation_type,title,severity,asset,details,fingerprint) VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) ON CONFLICT (run_id,fingerprint) DO UPDATE SET title=EXCLUDED.title,severity=EXCLUDED.severity,asset=EXCLUDED.asset,details=EXCLUDED.details""", records)
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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def prepare_schemathesis_schema(run: dict, run_dir: Path) -> Path:
    schema_url = str(run["base_url"])
    target = urlsplit(schema_url)
    target_host = (target.hostname or "").lower().rstrip(".")
    if target.scheme not in {"http", "https"} or not target_host:
        raise RuntimeError("Schemathesis schema URL must be HTTP(S)")
    allowed_hosts = {
        str(host).lower().rstrip(".") for host in (run.get("allowed_hosts") or [])
    }
    if target_host not in allowed_hosts:
        raise RuntimeError("Schemathesis schema host is outside the saved scope")

    opener = urllib.request.build_opener(_NoRedirectHandler())
    request = urllib.request.Request(
        schema_url,
        headers={"User-Agent": "security-platform-schema-fetch/1.0", "Accept": "application/json, application/yaml, text/yaml"},
    )
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(MAX_API_SCHEMA_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not fetch API schema without redirects: {exc}") from exc
    if len(raw) > MAX_API_SCHEMA_BYTES:
        raise RuntimeError("API schema exceeds the 5 MiB limit")
    try:
        text = raw.decode("utf-8")
        try:
            schema = json.loads(text)
        except json.JSONDecodeError:
            schema = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RuntimeError("API schema is not valid UTF-8 JSON/YAML") from exc
    if not isinstance(schema, dict) or not (schema.get("openapi") or schema.get("swagger")):
        raise RuntimeError("Target did not return an OpenAPI schema")
    paths = schema.get("paths") or {}
    if not isinstance(paths, dict) or len(paths) > 1000:
        raise RuntimeError("API schema has an invalid or excessive paths section")

    def validate(value) -> None:
        if isinstance(value, dict):
            reference = value.get("$ref")
            if isinstance(reference, str):
                parsed = urlsplit(reference)
                if parsed.scheme or parsed.netloc:
                    raise RuntimeError("Remote OpenAPI references are not permitted")
            servers = value.get("servers")
            if isinstance(servers, list):
                for server in servers:
                    if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                        continue
                    parsed = urlsplit(server["url"])
                    server_host = (parsed.hostname or "").lower().rstrip(".")
                    if server_host and server_host != target_host:
                        raise RuntimeError("OpenAPI server URL is outside the authorized host")
            for child in value.values():
                validate(child)
        elif isinstance(value, list):
            for child in value:
                validate(child)

    validate(schema)
    schema_file = run_dir / "schema.json"
    schema_file.write_text(json.dumps(schema, separators=(",", ":")) + "\n", encoding="utf-8")
    schema_file.chmod(0o644)
    return schema_file


def prepare_dnsx_input(run: dict, run_dir: Path) -> Path:
    if not run.get("dns_resolver"):
        raise ValueError("dnsx requires an explicitly approved DNS resolver")
    host = (urlsplit(run["base_url"]).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("dnsx target must contain a hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("dnsx requires a DNS hostname, not an IP literal")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("dnsx target hostname is invalid")
    input_file = run_dir / "dnsx-hosts.txt"
    input_file.write_text(host + "\n", encoding="utf-8")
    input_file.chmod(0o644)
    return input_file


def prepare_massdns_input(run: dict, run_dir: Path) -> tuple[Path, Path]:
    if not run.get("dns_resolver"):
        raise ValueError("massdns requires an explicitly approved DNS resolver")
    host = (urlsplit(run["base_url"]).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("massdns target must contain a hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("massdns requires a DNS hostname, not an IP literal")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("massdns target hostname is invalid")
    hosts_file = run_dir / "massdns-hosts.txt"
    resolver_file = run_dir / "massdns-resolvers.txt"
    hosts_file.write_text(host + "\n", encoding="utf-8")
    resolver_file.write_text(str(run["dns_resolver"]) + "\n", encoding="utf-8")
    hosts_file.chmod(0o644)
    resolver_file.chmod(0o644)
    return hosts_file, resolver_file


def prepare_dnsrecon_input(run: dict, run_dir: Path) -> Path:
    if not run.get("dns_resolver"):
        raise ValueError("dnsrecon requires an explicitly approved DNS resolver")
    host = (urlsplit(run["base_url"]).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("dnsrecon target must contain a hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("dnsrecon requires a DNS hostname, not an IP literal")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("dnsrecon target hostname is invalid")
    raw_file = run_dir / "dnsrecon-raw.json"
    raw_file.write_text("[]\n", encoding="utf-8")
    raw_file.chmod(0o600)
    return raw_file


def prepare_playwright_input(run: dict, run_dir: Path) -> tuple[Path, Path]:
    target = urlsplit(run["base_url"])
    target_host = (target.hostname or "").lower().rstrip(".")
    if target.scheme not in {"http", "https"} or not target_host:
        raise ValueError("Playwright target must be an HTTP(S) URL")
    excluded = []
    for raw_path in run.get("excluded_paths") or []:
        path = "/" + str(raw_path).lstrip("/")
        excluded.append(path.rstrip("/") or "/")
    target_path = target.path or "/"
    if any(blocked == "/" or target_path == blocked or target_path.startswith(blocked + "/") for blocked in excluded):
        raise ValueError("Playwright target URL is inside an excluded path")
    config_file = run_dir / "browser-config.json"
    config_file.write_text(json.dumps({
        "target": run["base_url"],
        "allowed_host": target_host,
        "excluded_paths": excluded,
        "navigation_timeout_ms": 15000,
    }, separators=(",", ":")) + "\n", encoding="utf-8")
    config_file.chmod(0o644)
    script_file = run_dir / "browser-observe.js"
    script_file.write_text(r'''const fs = require("fs");
const { chromium } = require("/usr/lib/node_modules/playwright");
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const cleanUrl = value => { const u = new URL(value); return `${u.protocol}//${u.host}${u.pathname}`; };
const blockedPath = pathname => config.excluded_paths.some(p => p === "/" || pathname === p || pathname.startsWith(p + "/"));
(async () => {
  let browser;
  const metrics = { same_origin_requests: 0, blocked_requests: 0, failed_requests: 0, console_errors: 0, page_errors: 0 };
  try {
    browser = await chromium.launch({headless: true, args: ["--disable-dev-shm-usage"]});
    const context = await browser.newContext({serviceWorkers: "block", acceptDownloads: false});
    const page = await context.newPage();
    page.on("console", message => { if (message.type() === "error") metrics.console_errors += 1; });
    page.on("pageerror", () => { metrics.page_errors += 1; });
    page.on("requestfailed", () => { metrics.failed_requests += 1; });
    await page.route("**/*", async route => {
      try {
        const u = new URL(route.request().url());
        const host = u.hostname.toLowerCase().replace(/\.$/, "");
        if ((u.protocol === "http:" || u.protocol === "https:") && host === config.allowed_host && !blockedPath(u.pathname)) {
          metrics.same_origin_requests += 1;
          return route.continue();
        }
      } catch (_) {}
      metrics.blocked_requests += 1;
      return route.abort("blockedbyclient");
    });
    const response = await page.goto(config.target, {waitUntil: "domcontentloaded", timeout: config.navigation_timeout_ms});
    await page.waitForTimeout(500);
    const result = {
      kind: "browser-observation",
      requested_url: cleanUrl(config.target),
      final_url: cleanUrl(page.url()),
      title: (await page.title()).slice(0, 500),
      status_code: response ? response.status() : 0,
      content_type: response ? String((await response.allHeaders())["content-type"] || "").slice(0, 200) : "",
      ...metrics,
    };
    console.log(JSON.stringify(result));
    await context.close();
  } catch (error) {
    console.error(JSON.stringify({kind: "browser-error", name: String(error && error.name || "Error").slice(0, 80)}));
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
  }
})();
''', encoding="utf-8")
    script_file.chmod(0o644)
    return script_file, config_file


def prepare_kiterunner_wordlist(run: dict, run_dir: Path) -> Path:
    routes = []
    for raw_line in KITERUNNER_WORDLIST_RUNNER_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        route = "/" + line.lstrip("/")
        route = route.rstrip("/") or "/"
        routes.append(route)

    excluded = []
    for raw_path in run.get("excluded_paths") or []:
        path = "/" + str(raw_path).lstrip("/")
        excluded.append(path.rstrip("/") or "/")

    filtered = [
        route for route in routes
        if not any(
            blocked == "/" or route == blocked or route.startswith(blocked + "/")
            for blocked in excluded
        )
    ]
    if not filtered:
        raise ValueError("No reviewed Kiterunner routes remain after applying exclusions")
    wordlist = run_dir / "kiterunner-routes.txt"
    wordlist.write_text("\n".join(filtered) + "\n", encoding="utf-8")
    wordlist.chmod(0o644)
    return wordlist


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

    zap_scope_file = run_dir / "zap-scope.conf"
    zap_scope_hook = run_dir / "zap-scope-hook.py"
    if run["tool_id"] in {"zap-passive", "zap-baseline", "zap-full"} and run["excluded_paths"]:
        target = urlsplit(run["base_url"])
        origin = f"{target.scheme}://{target.netloc}"
        rules = []
        for excluded_path in run["excluded_paths"]:
            normalized = "/" + str(excluded_path).lstrip("/")
            normalized = normalized.rstrip("/") or "/"
            pattern = rf"^{re.escape(origin)}{re.escape(normalized)}(?:/.*)?(?:[?#].*)?$"
            rules.append(f"*\tOUTOFSCOPE\t{pattern}")
        zap_scope_file.write_text("\n".join(rules) + "\n", encoding="utf-8")
        hook_patterns = [rule.split("\t", 2)[2] for rule in rules]
        zap_scope_hook.write_text(
            "EXCLUDED_PATTERNS = " + json.dumps(hook_patterns) + "\n\n"
            "def zap_started(zap, target):\n"
            "    for pattern in EXCLUDED_PATTERNS:\n"
            "        zap.spider.exclude_from_scan(pattern)\n",
            encoding="utf-8",
        )

    metadata_file.write_text(
        json.dumps(
            {
                "run_id": str(run_id),
                "tool_id": run["tool_id"],
                "profile": run["profile"],
                "input_type": input_type,
                "target": (
                    urlsplit(run["base_url"])._replace(query="", fragment="").geturl()
                    if input_type == "target" and run["tool_id"] == "playwright"
                    else run["base_url"] if input_type == "target" else None
                ),
                "source_artifact_id": str(run["source_artifact_id"]) if run["source_artifact_id"] else None,
                "source_filename": run["source_filename"],
                "source_sha256": run["source_sha256"],
                "image": adapter["image"],
                "allowed_hosts": run["allowed_hosts"] if input_type == "target" else [],
                "excluded_paths": run["excluded_paths"] if input_type == "target" else [],
                "dns_resolver": run["dns_resolver"] if input_type == "target" else None,
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
    kics_captured = False
    kics_exit_code = 1
    try:
        client = docker.from_env()
        resources = adapter.get("resources", {})
        memory = resources.get("memory", "512m")
        cpus = float(resources.get("cpus", 0.5))
        pids = int(resources.get("pids", 128))
        timeout_seconds = max(30, min(int(adapter.get("timeout_seconds", 600)), 7200))
        schemathesis_schema_file = None
        if run["tool_id"] == "schemathesis":
            schemathesis_schema_file = prepare_schemathesis_schema(run, run_dir)
        if run["tool_id"] == "dnsx":
            prepare_dnsx_input(run, run_dir)
        if run["tool_id"] == "massdns":
            prepare_massdns_input(run, run_dir)
        if run["tool_id"] == "dnsrecon":
            prepare_dnsrecon_input(run, run_dir)
        if run["tool_id"] == "playwright":
            prepare_playwright_input(run, run_dir)
        if run["tool_id"] == "kiterunner":
            prepare_kiterunner_wordlist(run, run_dir)
        command = build_command(
            run["tool_id"], run["base_url"], adapter, run["excluded_paths"], run["dns_resolver"]
        )
        if run["tool_id"] == "codeql":
            command = build_codeql_command(codeql_languages(source_container_path))
        if run["tool_id"] == "shellcheck":
            shell_files = sorted(
                f"/src/{path.relative_to(source_container_path).as_posix()}"
                for path in source_container_path.rglob("*.sh")
                if path.is_file()
            )
            command = ["-f", "json1", *(shell_files or ["/dev/null"])]
        container_volumes = {}
        if input_type == "source":
            container_volumes[str(source_host_path)] = {"bind": "/src", "mode": "ro"}
            if run["tool_id"] == "semgrep":
                container_volumes[SEMGREP_RULES_HOST_PATH] = {"bind": "/rules/semgrep-reviewed.yaml", "mode": "ro"}
            if run["tool_id"] == "trivy":
                container_volumes[TRIVY_CACHE_HOST_PATH] = {"bind": "/cache", "mode": "ro"}
            if run["tool_id"] == "osv-scanner":
                container_volumes[OSV_CACHE_HOST_PATH] = {"bind": "/cache", "mode": "ro"}
            if run["tool_id"] == "grype":
                container_volumes[GRYPE_CACHE_HOST_PATH] = {"bind": "/cache", "mode": "ro"}
            if run["tool_id"] == "codeql":
                container_volumes[CODEQL_CACHE_HOST_PATH] = {"bind": "/tmp/.codeql", "mode": "rw"}
            if run["tool_id"] == "kubescape":
                container_volumes[KUBESCAPE_POLICY_HOST_PATH] = {"bind": "/policies/nsa.json", "mode": "ro"}
        elif run["tool_id"] == "nuclei-reviewed":
            container_volumes[NUCLEI_TEMPLATES_HOST_PATH] = {"bind": "/templates", "mode": "ro"}
        elif run["tool_id"] == "schemathesis":
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "schema.json")] = {"bind": "/schema/openapi.json", "mode": "ro"}
        elif run["tool_id"] == "dnsx":
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "dnsx-hosts.txt")] = {
                "bind": "/input/hosts.txt",
                "mode": "ro",
            }
        elif run["tool_id"] == "massdns":
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "massdns-hosts.txt")] = {
                "bind": "/input/hosts.txt", "mode": "ro",
            }
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "massdns-resolvers.txt")] = {
                "bind": "/input/resolvers.txt", "mode": "ro",
            }
        elif run["tool_id"] == "dnsrecon":
            container_volumes[DNSRECON_WORDLIST_HOST_PATH] = {
                "bind": "/input/words.txt", "mode": "ro",
            }
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "dnsrecon-raw.json")] = {
                "bind": "/output/raw.json", "mode": "rw",
            }
        elif run["tool_id"] == "playwright":
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "browser-observe.js")] = {
                "bind": "/input/browser-observe.js", "mode": "ro",
            }
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "browser-config.json")] = {
                "bind": "/input/browser-config.json", "mode": "ro",
            }
        elif run["tool_id"] in {"feroxbuster", "ffuf", "gobuster"}:
            container_volumes[FFUF_WORDLIST_HOST_PATH] = {"bind": "/wordlists/content.txt", "mode": "ro"}
        elif run["tool_id"] == "kiterunner":
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "kiterunner-routes.txt")] = {
                "bind": "/wordlists/routes.txt",
                "mode": "ro",
            }
        elif run["tool_id"] == "arjun":
            container_volumes[ARJUN_WORDLIST_HOST_PATH] = {"bind": "/wordlists/parameters.txt", "mode": "ro"}
        if run["tool_id"] in {"zap-passive", "zap-baseline", "zap-full"} and run["excluded_paths"]:
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "zap-scope.conf")] = {
                "bind": "/zap/wrk/scope.conf",
                "mode": "ro",
            }
            container_volumes[str(EVIDENCE_HOST_ROOT / str(run_id) / "zap-scope-hook.py")] = {
                "bind": "/zap/wrk/scope-hook.py",
                "mode": "ro",
            }
        container = client.containers.run(
            adapter["image"],
            command=command,
            name=f"security-run-{run_id}",
            detach=True,
            # testssl and ZAP need ephemeral writable image layers for their own runtimes.
            # They remain non-root, capability-free, resource-limited, and are removed after each run.
            read_only=run["tool_id"] not in {"schemathesis", "testssl", "wapiti", "zap-passive", "zap-baseline", "zap-full"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=memory,
            nano_cpus=int(cpus * 1_000_000_000),
            pids_limit=pids,
            network_mode="none" if input_type == "source" else "bridge",
            user=adapter.get("user"),
            environment=(
                {"HOME": "/tmp", "CODEQL_SEARCH_PATH": "/opt/codeql-repo"}
                if run["tool_id"] == "codeql" else
                {"HOME": "/tmp", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1"}
                if run["tool_id"] == "playwright" else
                {"HOME": "/tmp"}
                if run["tool_id"] in {"dnsrecon", "dnsx", "massdns"} else
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
                if run["tool_id"] == "kubescape" else
                {"HOME": "/tmp"}
                if run["tool_id"] == "trufflehog" else
                {"HOME": "/tmp", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"}
                if run["tool_id"] == "osv-scanner" else
                {"HOME": "/tmp", "GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_CACHE_DIR": "/cache"}
                if run["tool_id"] == "grype" else
                {"HOME": "/tmp"}
                if run["tool_id"] in {"schemathesis", "sqlmap-controlled"} else
                {"HOME": "/tmp", "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_CACHE_DIR": "/tmp"}
                if run["tool_id"] == "syft" else
                {"HOME": "/tmp", "XDG_CONFIG_HOME": "/tmp/.config", "SEMGREP_SETTINGS_FILE": "/tmp/settings.yml", "SEMGREP_SEND_METRICS": "off"}
                if run["tool_id"] == "njsscan" else
                {"HOME": "/tmp/trivy-home", "XDG_CACHE_HOME": "/tmp/trivy-xdg"}
                if run["tool_id"] == "trivy" else None
            ),
            working_dir="/src" if input_type == "source" else "/tmp" if run["tool_id"] in {"schemathesis", "sqlmap-controlled", "testssl"} else "/zap/wrk" if run["tool_id"] in {"zap-passive", "zap-baseline", "zap-full"} else None,
            entrypoint={"zap-passive": "zap-baseline.py", "zap-baseline": "zap-baseline.py", "zap-full": "zap-full-scan.py", "trivy": "/bin/sh", "hadolint": "/bin/sh", "kics": "/bin/sh", "dalfox": "./dalfox", "playwright": "node", "codeql": "/bin/sh"}.get(run["tool_id"]),
            # testssl and ZAP reports must survive process exit long enough for docker cp.
            # Their writable container layers are ephemeral and removed in finally.
            tmpfs=(
                None if run["tool_id"] in {"schemathesis", "testssl", "wapiti", "zap-passive", "zap-baseline", "zap-full"}
                else {
                    "/tmp": (
                        "rw,nosuid,nodev,size=2g"
                        if run["tool_id"] == "codeql"
                        else
                        "rw,nosuid,nodev,noexec,size=128m"
                        if run["tool_id"] in {"kics", "kubescape"}
                        else "rw,nosuid,nodev,noexec,size=64m"
                    ),
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
                    **(
                        {"/home/scanner": "rw,nosuid,nodev,noexec,size=8m,uid=1000,gid=1000,mode=0700"}
                        if run["tool_id"] == "kiterunner"
                        else {}
                    ),
                }
            ),
            labels={
                "security-platform.run-id": str(run_id),
                "security-platform.tool": run["tool_id"],
            },
            volumes=container_volumes or None,
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
            if run["tool_id"] == "kics" and container.status == "running":
                marker = container.exec_run(["test", "-f", "/tmp/.reports-ready"])
                if marker.exit_code == 0:
                    status = container.exec_run(["cat", "/tmp/.kics-exit"])
                    if status.exit_code != 0:
                        raise RuntimeError("KICS exit status marker could not be read")
                    kics_exit_code = int(status.output.decode("utf-8").strip())
                    if kics_exit_code == 0:
                        capture_kics_output(container, output_file)
                    kics_captured = True
                    container.stop(timeout=2)
                    break
            if container.status in {"exited", "dead"}:
                break
            time.sleep(POLL_SECONDS)

        result = container.wait(timeout=10)
        logs = container.logs(stdout=True, stderr=True)
        exit_code = (
            0 if trivy_captured else
            kics_exit_code if kics_captured else
            int(result.get("StatusCode", 1))
        )
        if run["tool_id"] == "testssl":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code == 0:
                capture_testssl_output(container, output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "schemathesis":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code in {0, 1}:
                capture_json_output(container, "/tmp/report.json", output_file)
                write_schemathesis_output(output_file.read_bytes(), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] in {"zap-passive", "zap-baseline", "zap-full"}:
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
        elif run["tool_id"] == "gobuster":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_gobuster_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "feroxbuster":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_feroxbuster_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "dnsx":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_dnsx_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"results": [], "error": "dnsx execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "massdns":
            (run_dir / "tool.log").write_text(
                "MassDNS raw resolver and packet output omitted; A records normalized.\n",
                encoding="utf-8",
            )
            if exit_code == 0:
                write_massdns_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"results": [], "error": "MassDNS execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "dnsrecon":
            raw_file = run_dir / "dnsrecon-raw.json"
            if exit_code == 0:
                (run_dir / "tool.log").write_text(
                    "DNSRecon raw resolver output and invocation metadata omitted; A records normalized.\n",
                    encoding="utf-8",
                )
                write_dnsrecon_output(raw_file, output_file)
            else:
                diagnostic = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")[-4096:]
                host = (urlsplit(run["base_url"]).hostname or "").lower().rstrip(".")
                for sensitive in (str(run.get("dns_resolver") or ""), host, "/input/words.txt", "/output/raw.json"):
                    if sensitive:
                        diagnostic = diagnostic.replace(sensitive, "[OMITTED]")
                (run_dir / "tool.log").write_text(
                    diagnostic or "DNSRecon execution failed; diagnostic output unavailable.\n",
                    encoding="utf-8",
                )
                output_file.write_text(
                    json.dumps({"results": [], "error": "DNSRecon execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
            raw_file.unlink(missing_ok=True)
        elif run["tool_id"] == "playwright":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_playwright_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"kind": "browser-observation", "error": "Playwright execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "codeql":
            (run_dir / "tool.log").write_text(
                "CodeQL raw build and query logs omitted; normalized SARIF retained.\n",
                encoding="utf-8",
            )
            if exit_code == 0:
                write_codeql_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"results": [], "error": "CodeQL execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "kiterunner":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_kiterunner_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"results": [], "error": "Kiterunner execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "semgrep":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_semgrep_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "dalfox":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code in {0, 1}:
                write_dalfox_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "sqlmap-controlled":
            (run_dir / "tool.log").write_text(
                "SQLmap raw console output omitted; findings and payloads sanitized.\n",
                encoding="utf-8",
            )
            if exit_code == 0:
                write_sqlmap_output(logs, output_file)
            else:
                output_file.write_text(
                    json.dumps({"findings": [], "error": "SQLmap execution failed; raw console omitted"}) + "\n",
                    encoding="utf-8",
                )
        elif run["tool_id"] == "syft":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_syft_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "grype":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_grype_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "checkov":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                write_checkov_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "kubescape":
            (run_dir / "tool.log").write_text(
                "Kubescape raw report omitted; failed controls normalized without manifests or fix paths.\n",
                encoding="utf-8",
            )
            if exit_code == 0:
                write_kubescape_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_text(
                    json.dumps({"results": [], "error": "Kubescape execution failed; raw output omitted"}) + "\n",
                    encoding="utf-8",
                )
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
        elif run["tool_id"] == "osv-scanner":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code in {0, 1}:
                write_osv_output(container.logs(stdout=True, stderr=False), output_file)
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "njsscan":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code == 0:
                output_file.write_bytes(container.logs(stdout=True, stderr=False))
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "brakeman":
            (run_dir / "tool.log").write_bytes(container.logs(stdout=False, stderr=True))
            if exit_code in {0, 3}:
                output_file.write_bytes(container.logs(stdout=True, stderr=False))
            else:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "kics":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code != 0:
                output_file.write_bytes(logs)
        elif run["tool_id"] == "trivy":
            (run_dir / "tool.log").write_bytes(logs)
            if exit_code != 0:
                output_file.write_bytes(logs)
        else:
            output_file.write_bytes(logs)
        successful_exit_codes = {0, 1, 2} if run["tool_id"] in {"zap-passive", "zap-baseline", "zap-full"} else {0, 3} if run["tool_id"] == "brakeman" else {0, 1} if run["tool_id"] in {"dalfox", "gitleaks", "hadolint", "njsscan", "osv-scanner", "schemathesis", "shellcheck"} else {0}
        if exit_code in successful_exit_codes:
            normalizers = {"arjun": normalize_arjun, "bandit": normalize_bandit, "brakeman": normalize_brakeman, "checkov": normalize_checkov, "codeql": normalize_codeql, "dalfox": normalize_dalfox, "dnsrecon": normalize_dnsrecon, "dnsx": normalize_dnsx, "feroxbuster": normalize_feroxbuster, "ffuf": normalize_ffuf, "gitleaks": normalize_gitleaks, "gobuster": normalize_gobuster, "grype": normalize_grype, "hadolint": normalize_hadolint, "httpx": normalize_httpx, "katana": normalize_katana, "kics": normalize_kics, "kiterunner": normalize_kiterunner, "kubescape": normalize_kubescape, "massdns": normalize_massdns, "naabu": normalize_naabu, "nikto": normalize_nikto, "njsscan": normalize_njsscan, "nmap": normalize_nmap, "nuclei-reviewed": normalize_nuclei, "osv-scanner": normalize_osv, "playwright": normalize_playwright, "schemathesis": normalize_schemathesis, "semgrep": normalize_semgrep, "shellcheck": normalize_shellcheck, "sqlmap-controlled": normalize_sqlmap, "subfinder": normalize_subfinder, "syft": normalize_syft, "testssl": normalize_testssl, "trivy": normalize_trivy, "trufflehog": normalize_trufflehog, "wapiti": normalize_wapiti, "zap-passive": normalize_zap, "zap-baseline": normalize_zap, "zap-full": normalize_zap}
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
        if run["tool_id"] == "playwright":
            for temporary_name in ("browser-observe.js", "browser-config.json"):
                try:
                    (run_dir / temporary_name).unlink(missing_ok=True)
                except OSError:
                    pass
        if run["tool_id"] == "dnsrecon":
            try:
                (run_dir / "dnsrecon-raw.json").unlink(missing_ok=True)
            except OSError:
                pass
        if run["tool_id"] == "dnsx":
            try:
                (run_dir / "dnsx-hosts.txt").unlink(missing_ok=True)
            except OSError:
                pass
        if run["tool_id"] == "massdns":
            for temporary_name in ("massdns-hosts.txt", "massdns-resolvers.txt"):
                try:
                    (run_dir / temporary_name).unlink(missing_ok=True)
                except OSError:
                    pass
        if client is not None:
            client.close()
        try:
            seal_evidence(run_id, run_dir)
        except (OSError, ValueError, psycopg.Error) as exc:
            set_status(run_id, "failed", f"Evidence sealing failed: {str(exc)[:900]}")


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
