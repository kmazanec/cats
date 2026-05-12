# CATS — Copilot Automated Tactical Security

Adversarial multi-agent platform that continuously probes the OpenEMR Clinical
Co-Pilot for vulnerabilities. Sibling to `openemr/`; read-only relationship to
the target.

- Architecture: [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- Threat model: [`THREAT_MODEL.md`](./THREAT_MODEL.md)
- Personas + workflows: [`USERS.md`](./USERS.md)
- Roadmap: [`docs/ROADMAP.md`](./docs/ROADMAP.md)
- Production deploy: [`docs/DEPLOY.md`](./docs/DEPLOY.md)

## Prereqs

- Python 3.12, [uv](https://github.com/astral-sh/uv), Docker.

## First-time setup

```bash
cp .env.example .env
# At minimum, set:
#   CATS_ADMIN_EMAIL=you@example.com
#   CATS_ADMIN_PASSWORD=<8+ chars>
#   CATS_SESSION_SECRET=$(openssl rand -hex 32)
```

## Run everything in Docker (recommended)

```bash
docker compose up -d --build   # postgres + redis + api (auto-migrates on boot)
open http://localhost:8400     # dashboard
```

The `api` service runs Alembic migrations on startup, hot-reloads from
`./src`, and seeds the bootstrap admin from `CATS_ADMIN_EMAIL` /
`CATS_ADMIN_PASSWORD`.

## Run on the host (for fast iteration / debugging)

```bash
uv sync --all-extras
docker compose up -d postgres redis   # just the data plane
make migrate
make api                              # FastAPI on :8400
```

## Day-to-day

```bash
make smoke               # end-to-end no-LLM smoke
make test                # full pytest suite (unit + integration)
make test-unit           # unit only — no postgres needed
make lint                # ruff check + ruff format --check + mypy strict
cats --help
cats health              # reachability check against every external dep
cats user create me@x --role operator
```

---

## Walkthrough — register your first target in under 10 minutes

The Round 1 DoD asks that a new engineer can stand CATS up and register a
target end-to-end without spelunking. Here it is:

1. **Clone and configure** (≈ 2 min)

   ```bash
   git clone <repo url> cats && cd cats
   cp .env.example .env
   # Edit .env: set CATS_ADMIN_EMAIL, CATS_ADMIN_PASSWORD, CATS_SESSION_SECRET.
   ```

2. **Bring up the stack** (≈ 3 min, dominated by the docker build)

   ```bash
   docker compose up -d --build
   ```

3. **Reachability check** (≈ 30 sec)

   ```bash
   docker compose exec api cats health
   # Expect: postgres ok, redis ok, openrouter/langsmith not_configured (fine in dev).
   ```

4. **Sign in** (≈ 30 sec)

   - Open <http://localhost:8400/> — you'll be redirected to `/login`.
   - Sign in with the `CATS_ADMIN_EMAIL` / `CATS_ADMIN_PASSWORD` from your
     `.env`.

5. **Register the deployed Co-Pilot as your first Project** (≈ 1 min)

   - Click **Projects** → **register project**.
   - Name: e.g. `OpenEMR Co-Pilot — local`
   - Base URL: `http://host.docker.internal:8300` (or wherever your
     Co-Pilot lives)
   - Env: `local` (or `staging` / `prod` as appropriate)
   - Leave **allow_run_against** unchecked for now — Round 1 only
     registers targets; Round 2 introduces the runner.

6. **Verify the audit trail** (≈ 30 sec)

   - Click **Audit** in the top nav.
   - You should see two entries with your email as the actor:
     `auth.login` and `project.create`. Both are append-only at the
     database level — the Postgres trigger blocks UPDATE/DELETE.

7. **(Optional) Add an operator account** (≈ 1 min)

   ```bash
   docker compose exec api cats user create operator@example.com --role operator
   ```

   Or use the **Users** page (admin-only) in the dashboard.

That's the round. Past this point you have a real, role-gated, audit-logged
multi-user dashboard with reachability monitoring and a deploy pipeline
ready to ship to <https://cats.biograph.dev>. Round 2 turns the
"register a target" surface into "actually attack a target."

---

## Layout

```
src/cats/
  api/         # FastAPI + HTMX dashboard (login, projects, users, audit, health)
  health/      # reachability checks (postgres / redis / openrouter / langsmith)
  models/      # Pydantic domain models
  db/          # SQLAlchemy schema + repositories
  graph/       # LangGraph state machine (Round 2+)
  agents/      # role-specific prompts + policy (Round 2+)
  categories/  # attack-category plugins (Round 2+)
  output_filter/
  target/      # HTTP client into the target co-pilot
  llm/         # OpenRouter wrapper + model registry
  events/      # Redis pub/sub
  cli/
  workers/
```
