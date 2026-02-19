# syntax=docker/dockerfile:1

FROM python:3.13-alpine
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app

# Install dependencies only (cached layer, rebuilds only when lock changes)
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=ovh_dns_manager/__init__.py,target=ovh_dns_manager/__init__.py \
    uv sync --locked --no-install-project --no-dev

# Copy application code and install project
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Security: non-root user
RUN addgroup -g 10001 app && \
    adduser -u 10001 -G app -S -h /home/app app
USER app

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["ovh-dns-manager"]
