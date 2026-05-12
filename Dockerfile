FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uv

WORKDIR /app

# Install deps first (cache-friendly) without project source so a code change
# doesn't invalidate the dep layer.
COPY pyproject.toml ./
RUN uv pip install --system \
        fastapi uvicorn[standard] sse-starlette jinja2 python-multipart \
        pydantic pydantic-settings \
        sqlalchemy[asyncio] asyncpg alembic redis httpx typer structlog \
        langgraph "langgraph-checkpoint>=4.0.0" langgraph-checkpoint-postgres \
        langsmith langchain-openai

# Now copy source + migrations. In dev these are volume-mounted on top so
# changes hot-reload; in prod they're baked in.
COPY README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./

# Install the project itself so `cats` console_script + `cats` package are on
# PYTHONPATH (--no-deps because deps are already installed above).
RUN uv pip install --system --no-deps -e .

EXPOSE 8400

CMD ["uvicorn", "cats.api.app:app", "--host", "0.0.0.0", "--port", "8400"]
