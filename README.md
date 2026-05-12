# CATS — Copilot Automated Tactical Security

Adversarial multi-agent platform that continuously probes the OpenEMR Clinical
Co-Pilot for vulnerabilities. Sibling to `openemr/`; read-only relationship to
the target. See `../W3_ARCHITECTURE.md` for the full design.

## Prereqs

- Python 3.12, [uv](https://github.com/astral-sh/uv), Docker.

## First-time setup

```bash
cp .env.example .env          # fill in OPENROUTER_API_KEY etc. (optional for smoke)
```

## Run everything in Docker (recommended)

```bash
docker compose up -d --build   # postgres + redis + api (auto-migrates on boot)
open http://localhost:8400     # dashboard
```

The `api` service runs migrations on startup and hot-reloads from `./src`.

## Run on the host (for fast iteration / debugging)

```bash
uv sync
docker compose up -d postgres redis   # just the data plane
make migrate
make api                              # FastAPI on :8400
```

## Day-to-day

```bash
make smoke      # end-to-end no-LLM smoke: writes Run/Attack/Execution/Verdict/Finding
make test       # pytest
make lint       # ruff + mypy strict
cats --help     # CLI
```

## Layout (one screen)

```
src/cats/
  models/      # Pydantic domain models
  db/          # SQLAlchemy schema + repositories
  graph/       # LangGraph state machine
  agents/      # role-specific prompts + policy
  categories/  # attack-category plugins (injection/exfil/tool_abuse)
  output_filter/
  target/      # HTTP client into the target co-pilot
  llm/         # OpenRouter wrapper + model registry
  api/         # FastAPI + HTMX
  events/      # Redis pub/sub
  cli/
  workers/
```
