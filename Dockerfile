# syntax=docker/dockerfile:1

# Base image is a build argument so the image can be built from a registry mirror or from
# a base that trusts a corporate TLS-inspection CA. The default is the official slim image.
ARG PYTHON_IMAGE=python:3.12-slim-trixie

# ---------------------------------------------------------------- build: resolve the venv
FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

RUN pip install uv==0.11.32

WORKDIR /src
COPY pyproject.toml uv.lock ./
# --locked: fail the build if uv.lock is out of date instead of silently re-resolving.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

# ---------------------------------------------------------------- runtime: no build tools
FROM ${PYTHON_IMAGE} AS runtime

# A fixed, unprivileged UID; the code below is owned by root, so the process cannot
# rewrite its own code even if an attacker gets code execution in it.
RUN groupadd --system --gid 10001 phishtriage \
 && useradd --system --uid 10001 --gid phishtriage --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin phishtriage

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
COPY config/settings.example.yaml ./config/
COPY app ./app

USER phishtriage
EXPOSE 8000

# --no-server-header: do not advertise the server software and version.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header"]
