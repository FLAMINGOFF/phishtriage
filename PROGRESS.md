# Progress

## Current milestone
M1 – Email parsing and IOC extraction (next)

## Done
- M0 – Skeleton: uv project, ruff/mypy/pytest/pre-commit, settings loader (.env +
  config/settings.yaml), FastAPI `/healthz` and `/readyz`, RQ worker and IMAP poller
  skeletons with real health checks, Alembic, Dockerfile and seven-service Docker Compose
  stack, GitHub Actions (ruff, mypy, pytest, pip-audit, gitleaks, compose smoke test).

## Open issues
- None yet

## Decision log
- RQ instead of Celery: simpler, enough for a single node (fixed by the plan).
- Secrets only from environment; `settings.yaml` feeds only the `policy` field and rejects
  unknown keys, so a key pasted into YAML is a startup error.
- Without `config/settings.yaml`, dev falls back to `settings.example.yaml` (zero-config
  demo); `APP_ENV=prod` refuses to fall back and refuses the dev `SECRET_KEY` or plain IMAP.
- `/healthz` is liveness only (no dependencies); `/readyz` checks PostgreSQL and Redis and
  hides error details from the client. Compose health uses `/readyz`.
- Worker health = "this container's RQ worker is registered in Redis with a fresh
  heartbeat"; poller health = "reached the mailbox within 3 poll intervals".
- RQ jobs use the JSON serializer instead of pickle: jobs only carry a report ID, and
  pickle would turn Redis write access into code execution in the worker.
- Web container runs `alembic upgrade head` before serving (single node, no extra one-shot
  service); worker and poller wait for web to be healthy.
- Containers: non-root UID 10001, code owned by root, read-only root filesystem with tmpfs
  `/tmp`, `cap_drop: ALL`, `no-new-privileges`; published ports bound to 127.0.0.1.
- Image tags pinned to exact versions (postgres 16.16, redis 7.4.12, GreenMail 2.1.15,
  Mailpit 1.34.0); Dependabot proposes updates.
- Starlette's TestClient now wants `httpx2`; it is a dev-only dependency. Outbound intel
  calls (M3) use `httpx` + `respx` as the plan specifies.
- CI installs uv with pip at a pinned version instead of a third-party setup action; one
  extra CI job runs `docker compose up --wait` to prove the M0 acceptance criterion.
- README.zh-CN.md added next to the English README (same convention as the author's other
  repositories).

## Manual steps for the user
- Optional: create a VirusTotal account and put `VT_API_KEY` in `.env`.
- Optional: request a URLhaus Auth-Key at https://auth.abuse.ch/ and put `URLHAUS_AUTH_KEY` in `.env`.
- GitHub repository settings: add the topics `phishing`, `email-security`, `soc`,
  `threat-intelligence`, `fastapi`.
