# syntax=docker/dockerfile:1.7

ARG KINGFISHER_IMAGE=ghcr.io/mongodb/kingfisher:latest
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.6

FROM ${KINGFISHER_IMAGE} AS kingfisher-bin
FROM ${UV_IMAGE} AS uv-bin

FROM python:3.12-slim-bookworm AS python-builder

COPY --from=uv-bin /uv /uvx /usr/local/bin/

WORKDIR /build
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY pyproject.toml uv.lock .python-version ./
COPY packages/sec-gate/pyproject.toml packages/sec-gate/pyproject.toml
COPY packages/sec-gate/src packages/sec-gate/src

RUN uv sync --frozen --no-dev --no-editable --package sec-gate

FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="sec-gate" \
      org.opencontainers.image.description="Pluggable CI/CD security compliance gate wrapping MongoDB Kingfisher and SAST analyzers" \
      org.opencontainers.image.source="https://github.com/aksaha9/security-gate-ci" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=kingfisher-bin /usr/local/bin/kingfisher /usr/local/bin/kingfisher
COPY --from=python-builder /opt/venv /opt/venv
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/sec-gate/
COPY licenses/ /usr/share/licenses/sec-gate/

ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 secgate \
    && useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --create-home secgate \
    && kingfisher --version \
    && sec-gate list-plugins

USER 10001:10001
WORKDIR /workspace

ENTRYPOINT ["sec-gate"]
CMD ["run", "."]
