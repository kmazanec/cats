# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What CATS is

**CATS — Copilot Automated Tactical Security.** A continuously-running multi-agent adversarial-evaluation platform that probes the OpenEMR Clinical Co-Pilot (sibling repo `openemr/`, read-only) for vulnerabilities. Python 3.12 · LangGraph · FastAPI+HTMX · Postgres · Redis · OpenRouter · LangSmith.

Authoritative narrative lives in `ARCHITECTURE.md`, `THREAT_MODEL.md`, `USERS.md`, and `docs/ROADMAP.md`. Read those before making architectural claims — they are kept current, this file is not.

## Commands

Day-to-day uses `make` targets; everything runs under `uv`:

```bash
make sync         # uv sync --all-extras
make api          # uvicorn cats.api.app:app on :8400 (host mode)
make worker       # cats.workers.campaign_worker
make smoke        # end-to-end no-LLM smoke (cats smoke)
make test         # full pytest (unit + integration; needs postgres+redis)
make test-unit    # tests/unit only — no infra needed
make lint         # ruff check + ruff format --check + mypy strict
make fmt          # ruff format + ruff check --fix
make migrate      # alembic upgrade head
make revision MSG="..."   # alembic autogenerate
```

Single test: `uv run pytest tests/unit/test_csrf.py::test_name -xvs`. Integration tests require `docker compose up -d postgres redis` first. Tests marked `live_target` (`@pytest.mark.live_target`) hit real OpenRouter/OpenEMR — opt-in via `pytest -m live_target`, not run in CI.

Docker stack (data plane + API with hot-reload from `./src`):

```bash
docker compose up -d --build    # postgres+redis+api; api auto-runs alembic
open http://localhost:8400
docker compose exec api cats health     # external-dep reachability
docker compose exec api cats user create x@y.com --role operator
```

CLI entry point: `cats` (defined in `pyproject.toml` → `cats.cli.main:app`, Typer).

## Architecture orientation

CATS is **four independent agents around a typed Postgres-backed message bus**, *not* one big LangGraph. LangGraph is a *within-agent* implementation tool (the Red Team uses it internally); it is not the platform's coordination backbone. The four agents:

1. **Orchestrator** (`src/cats/agents/orchestrator/`) — LLM planner (Sonnet 4.6) that authors a `CampaignPlan`; human-gated approval before any attack fires.
2. **Red Team** (`src/cats/agents/red_team/`) — adversarial **LangGraph agent** (R10-followup). `agent.py` is the load-bearing graph: an `attacker` LLM node + a `tool_executor` node that dispatches four tools (`propose_attack`, `mutate_attack`, `fire_at_target`, `submit_for_judgment`). The agent owns multi-turn escalation in-conversation; it decides when to mutate, fire, and submit. Specialists are now the implementation of `propose_attack`. Output Filter still gates every payload before egress.
3. **Judge** (`src/cats/agents/judge/`) — independent (Haiku 4.5, different family from Red Team by policy); deterministic post-condition first, LLM rubric fallback. Held to a versioned ground-truth fixture set.
4. **Documentation** (`src/cats/agents/documentation/`) — writes Findings + report Markdown; pauses on `severity: critical` for human approval.

The Red Team's `agent.py` graph is the load-bearing LangGraph in the system. There's also a legacy `src/cats/graph/` (the pre-R10 specialist → mutator → filter → target → judge state machine) used by `cats.workers.campaign_worker.run_one` — that path still backs `make smoke` and the R3 integration tests, but the production workers go through the agent now. Specialists, Mutator, Output Filter, and Target Caller are *components* of the Red Team — they share state, they are not peer agents on the bus.

Trust boundaries (do not violate without explicit user direction):

- **Output Filter** (`src/cats/output_filter/`) sits on the Red Team's outbox — regex/NFKC + LLM classifier. Nothing leaves the Red Team without passing through it. New attack-generating code MUST route through the filter before any HTTP egress.
- **Projects allowlist + `allow_run_against` flag** — registering a target does not authorize running against it.
- **Audit log** — Postgres trigger blocks UPDATE/DELETE on `audit_log`. Every user/platform action logs. Don't bypass the repo layer.
- **CSRF** — every mutating route requires a matching `cats_csrf` cookie + token (header or `csrf_token` form field). Plain `client.post(...)` in tests will 403; use `tests/integration/conftest.py::csrf_post`.

## Code layout

```
src/cats/
  api/         FastAPI + HTMX (app factory + lifespan in app.py, Jinja in templates/, routes/ per resource)
  agents/      orchestrator | red_team | judge | documentation | mutator | common
  categories/  attack-category plugins: injection/ exfil/ tool_abuse/ + taxonomy.py + _base.py
  graph/       LangGraph state machine (Red Team internals): build.py, state.py, nodes/, checkpointer.py
  output_filter/   regex_scanner.py + llm_classifier.py (Red Team egress safety gate)
  target/      HTTP client into the target co-pilot (per-Project auth, rate limiting)
  llm/         OpenRouter wrapper (openrouter.py), model registry (models.py), FakeLLMClient seam (client.py)
  db/          SQLAlchemy schema.py + repositories/ (one per aggregate)
  events/      Redis pub/sub bus.py + types.py (live SSE channel for the UI)
  workers/     campaign_worker.py — long-running attack worker
  health/      reachability checks (postgres/redis/openrouter/langsmith)
  security/    crypto.py (Fernet for stored creds), csrf.py
  cli/         Typer app (main.py) + smoke.py
  config.py    Pydantic BaseSettings — see "Config DI" below
migrations/   Alembic; langgraph requires postgres checkpointer (NOT sqlite — CVE-2025-67644)
```

## Conventions worth knowing before editing

- **Strict mypy + ruff.** `make lint` is mandatory. Ruff selects `E,F,W,I,B,UP,SIM,RUF,ASYNC`; `B008` is intentionally allowed in `api/` (FastAPI's `Depends()` idiom).
- **Async everywhere.** SQLAlchemy is `asyncio`; engine is `asyncpg`; FastAPI routes and DB sessions are async. The `tests/integration/conftest.py::client` fixture resets the cached engine per-test because pytest-asyncio gives each test its own loop — don't add a module-level engine cache without thinking through the loop scoping.
- **Config DI.** Three accessors in `cats.config`: `get_settings()` (preferred, DI-friendly), the module-level `settings` singleton (legacy R1/R2 call sites), and `set_settings_for_test(**overrides)` for tests. Don't introduce new uses of monkeypatching settings — use `set_settings_for_test`.
- **LLM test seam.** `cats.llm.client.install_override(FakeLLMClient(...))` replaces the OpenRouter client process-globally for the duration of a test. The Red Team's graph nodes call `get_llm()`, which checks the override first. Always clean up (`install_override(None)`) in a `finally` or autouse fixture.
- **Outbound HTTP in tests.** Mock via `httpx.MockTransport` patched into `cats.target.client` (see `tests/integration/test_campaign_e2e.py::patch_target_transport`). Don't hit real OpenEMR from non-`live_target` tests.
- **LangGraph pins.** `langgraph-checkpoint>=4.0.0` (CVE-2026-27794) and `langgraph-checkpoint-postgres` (sqlite has CVE-2025-67644) — do NOT downgrade these or switch to the sqlite checkpointer.
- **`psycopg[binary]`** is pinned because langgraph's `AsyncPostgresSaver` imports `psycopg` directly; the binary wheel bundles libpq so the slim Docker image doesn't need apt libpq5. SQLAlchemy itself still uses asyncpg.
- **Sibling repo.** `openemr/` is the target; CATS has read-only access for threat-model grounding. Never import from it or write into it.

## Pre-commit checks

Before every commit that touches code, run `make lint` and `make test` and resolve any failures. Skip when the commit is purely non-code (Markdown docs, images, comments-only edits, `.env.example`/CI YAML with no executable Python change). When in doubt, run them — they're cheap relative to a broken main.

- Code change → `make lint && make test`
- Only `src/cats/api/` templates or static assets → `make lint` (skip tests)
- Pure docs (`*.md`, `docs/`, `ARCHITECTURE.md`, etc.) → skip both
- Test-only or fixture-only change → `make test` (lint still runs on the test file)

If `make test` is impractical locally (no postgres+redis), run `make test-unit` and say so in the commit/PR — don't silently skip.

## Roadmap awareness

Work is organized in **rounds** in `docs/ROADMAP.md`. Each round has `Goal`/`Outcome`/`DoD`/`Risks` pre-specified and `Tasks`/`Decisions`/`Retrospective` filled in as the round ships. Every round's DoD includes: end-to-end demoable, unit + integration tests, judge accuracy bar (when relevant), audit-logged, lint+typecheck clean, secrets-clean, and reaching the deployed URL via the GitLab CI rail in `.gitlab-ci.yml`. If you're picking up "the next round," the `/next-round` skill is the entry point.

## Things that look like bugs but aren't

(From `tests/README.md` — read that file before debugging test infra.)

- `RuntimeError: Event loop is closed` / "attached to a different loop" in tests → almost always a cached `_engine` from a prior test. The `client` fixture handles this; new fixtures must follow the same reset pattern.
- Background `asyncio.create_task` work from routes: the test client's lifespan exits before the task finishes. R2 e2e tests call `run_one` directly rather than going through the route.
- `redis.aclose()` with `# type: ignore` — redis 5.x types lag behind the runtime API.
- `LangChainPendingDeprecationWarning` from `langgraph.checkpoint.serde.jsonplus` at import time — filtered in `pyproject.toml`; no caller-side hook.
