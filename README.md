# Security Testing Platform

Private, self-hosted control plane for explicitly authorized website, API, and source-code security testing. The platform coordinates policy-bound Docker workers, records evidence, normalizes findings, tracks coverage, and supports human review and retesting.

The dashboard is bound to server localhost and is intended to be reached through an SSH tunnel. It is not a public scanner service.

## Current capabilities

- FastAPI control plane, PostgreSQL, Redis, and a multi-view web dashboard.
- Projects with reversible read-only archival, authorized targets, excluded paths, optional approved DNS resolvers, source archives, and encrypted test identities.
- 74 catalogued tools with 45 supervised adapters; adapter images are pinned by digest.
- Observe, controlled-active, extended-active, and source-assisted execution profiles.
- Reviewed single-tool runs plus ordered target and source-analysis workflow templates with cancellation and emergency stop.
- Dedicated Docker runner with read-only filesystems, dropped capabilities, non-root execution, resource limits, bounded output, and no Docker socket inside scanner containers.
- Live run events, normalized observations, deduplicated project findings, review states, notes, and bounded retests.
- Sealed evidence with integrity verification plus SARIF, DefectDojo JSON, Markdown, JSON, audit, coverage-gap, and report-bundle exports.
- Sanitized Burp Suite XML finding import. Raw requests, responses, cookies, and credentials are discarded; manual imports remain distinct from supervised coverage.
- Adapter readiness, storage and queue admission, deployment confinement, backup status, image audit history, and health monitoring.

Runtime proof is deliberately separate from implementation status. Adapters that depend on third-party discovery providers remain marked as requiring separate authorization until they are tested against an explicitly approved target.

## Safety model

Only test systems you own or are explicitly authorized to assess. Saved scope does not authorize third-party payment, identity, analytics, CDN, or hosting services.

The control plane enforces:

- explicit target or source authorization;
- exact-host and excluded-path output filtering;
- profile-specific rate, concurrency, timeout, and capability controls;
- separate opt-in for third-party discovery providers;
- immutable worker images and runtime-readiness admission;
- queue, storage, and evidence-capture limits;
- operator and read-only viewer roles;
- cancellation, emergency stop, audit events, and evidence integrity checks.

These controls reduce risk; they do not make aggressive production testing harmless. Production runs still require a reviewed scope, test window, monitoring, recovery plan, and a human operator.

## Architecture

| Service | Responsibility |
|---|---|
| `dashboard` | Private operator interface and API reverse proxy |
| `api` | Scope, policy, runs, findings, reports, and audit APIs |
| `runner` | Supervises short-lived scanner containers and evidence capture |
| `postgres` | Durable control-plane and finding metadata |
| `redis` | Run queue and coordination |

The Docker socket is mounted only into the dedicated runner supervisor. Tool containers do not receive the socket or unrestricted host paths.

## Private deployment

Prerequisites: Ubuntu, Docker Engine with Compose, Git, and an SSH account using public-key authentication.

1. Clone the repository on the private server.
2. Copy `.env.example` to `.env` and configure unique control-plane tokens, database credentials, credential-vault key, `LOCAL_UID`, and `DOCKER_GID`. Do not commit `.env`.
3. Validate and start the stack:

```bash
./ops/repository-check.sh
docker compose up -d --build
./ops/health-check.sh
./ops/smoke-test.sh
```

4. From the Windows workstation, create an SSH tunnel:

```text
ssh -N -L 8081:127.0.0.1:8080 killswitch@SERVER_LAN_IP
```

5. Open `http://127.0.0.1:8081` and unlock the dashboard with an operator or viewer token.

Keep PostgreSQL, Redis, the Docker API, and the dashboard listener off public network interfaces. Prefer a private LAN or VPN for remote access.

## Validation

`./ops/repository-check.sh` validates Compose confinement, adapter registry contracts, immutable images, and the backend unit suite. `./ops/smoke-test.sh` exercises authenticated control-plane reads, role enforcement, report schemas, evidence and backup status, sanitized import history, and service health.

Local validation scripts under `ops/` use disposable fixtures. They are the approved place to establish adapter proof without contacting live or external targets.

## Operations and recovery

- `ops/health-check.sh` writes the platform health snapshot used by the dashboard.
- `ops/backup.sh` creates one checksum-pinned recovery set containing PostgreSQL, configuration and operating scripts, sealed evidence, and imported source artifacts.
- `ops/validate-backup-restore.sh` verifies set checksums, rejects unsafe archive members, restores the database in isolation, and checks archived evidence/source content against the restored database seals.
- `ops/audit-image.sh` records image inventory, vulnerability audit output, SBOMs, and checksums.
- systemd units in `ops/systemd/` schedule health and backup jobs.

Backups should also be copied to a separate machine or encrypted off-host location. A backup is not considered reliable until restore validation succeeds.

## Development rule

Do not add a tool merely because it is available. A supervised adapter must define its immutable image, input type, execution profile, command builder, parser, scope enforcement, evidence limits, and local validation path. Manual and standalone tools stay clearly separated from automated coverage.
