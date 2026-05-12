FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uv

WORKDIR /app

# Install deps from the lockfile first (cache-friendly: this layer only
# invalidates when pyproject.toml/uv.lock change, not on source edits).
# --frozen forces uv.lock to be the source of truth — fails loudly if the
# lockfile is out of sync rather than silently resolving a different
# version. --no-install-project skips the editable cats install; we do it
# after source copy so the layer cache works.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Now copy source + migrations. In dev these are volume-mounted on top so
# changes hot-reload; in prod they're baked in.
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./

# Install the project itself (no-deps because uv sync already installed
# everything from the lockfile).
RUN uv pip install --no-deps -e .

# uv sync puts the venv at /app/.venv. Put it on PATH so plain
# `uvicorn`/`alembic` invocations resolve to the venv binaries without
# needing `uv run` (which fights with our PYTHONDONTWRITEBYTECODE etc).
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8400

CMD ["uvicorn", "cats.api.app:app", "--host", "0.0.0.0", "--port", "8400"]
