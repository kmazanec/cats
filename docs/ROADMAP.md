# CATS — Implementation Roadmap

> **Status:** working doc. Each round below is a self-contained,
> shippable iteration. Builders fill in the **Tasks**, **Decisions**,
> and **Retrospective** sections of a round as they complete it;
> the planning-level fields (Goal, Outcome, DoD, Risks) are
> pre-specified and should not drift.
>
> **Companions:**
> - [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — platform architecture
> - [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — target threat model
> - [`../USERS.md`](../USERS.md) — users and workflows
> - [`./W3_THREAT_RESEARCH.md`](./W3_THREAT_RESEARCH.md) — May-2026 attack-landscape research

---

## How this roadmap is organized

CATS is built in **rounds**. Each round ships an increment of
working product a user can pick up and use. The first two rounds
are larger by necessity: Round 1 stands up the platform's
foundations (users, targets, audit, reachability), and Round 2
lands the first end-to-end attack against the live target —
after Round 2, CATS *does* the thing it exists to do, even if
only one technique is covered. Round 3 deepens the first attack
category into a family. Round 4 brings the platform's strategic
decision-maker online — the LLM-driven Orchestrator
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4 describes, with a
human-in-the-loop plan approval gate. From Round 5 onward, each
round is **tightly scoped to a single attack category or technique
from the threat model**, deepening coverage rather than adding
internal machinery — but every campaign in those rounds flows
through the Orchestrator the platform learned to use in R4.

This shape exists to avoid the classic agile failure mode of "we
built lots of infrastructure but nothing demoable." After Round 2,
CATS *does* the thing; after Round 4, it *learns* to direct itself
under operator approval. Each round is meant to be small enough
to ship cleanly and self-contained enough that the user can see
the value before the next round starts.

### Definition of done — applies to every round

Every round, regardless of scope, must satisfy these gates before
it is considered complete:

1. **Demoable.** The round's stated outcome works end-to-end
   against the live target the round names — usually the
   deployed Co-Pilot.
2. **Tested at two levels.** Fast, deterministic tests cover the
   round's logic and run on every change. Slower, real-model
   evaluations run on a schedule (not on every change) to keep
   the judge honest.
3. **Evaluated where it matters.** When a round changes how the
   judge decides things, the round comes with an answer key the
   judge is measured against, and the agreed accuracy bar is met.
4. **Documented.** The round's `Tasks`, `Decisions`, and
   `Retrospective` sections in this doc are filled in. Any
   architectural change is reflected back into
   [`../ARCHITECTURE.md`](../ARCHITECTURE.md) or
   [`../THREAT_MODEL.md`](../THREAT_MODEL.md) as appropriate.
5. **Audit-logged.** Every action a user or the platform takes
   during the round is captured in the platform's audit trail
   — even in dev. The trust boundaries described in
   [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §6.1 are not
   optional for some environments.
6. **Engineering quality.** The platform's standard engineering
   quality checks pass — typing, linting, test suite — on every
   change. The specifics of those checks belong with the engineering
   contribution rules, not this product roadmap.
7. **Secrets-clean.** No real credentials in the repo, in
   commits, in test fixtures, or in logs.

### Cross-cutting workstreams

Some work is not a milestone — it threads through every round
and needs continuous attention rather than a single ship date.

- **Automated checks on every change.** From Round 1 forward,
  every change runs the platform's quality checks
  automatically. From Round 3 forward, a separate scheduled
  job exercises the judge against real models so we know it
  hasn't drifted.
- **Continuous deploy.** From Round 1 forward, every green
  change on the main branch reaches the deployed CATS URL
  automatically. Every round inherits this rail; a round
  isn't done until the change it shipped is reachable at the
  deployed URL, not just on a laptop. Failed deploys are
  visible, not silent, and the rollback path is always one
  command.
- **Security hygiene.** Keys, budgets, and credentials are
  managed conservatively from the first round and stay that
  way — every round inherits the discipline; no round gets to
  relax it.
- **Observability.** Once the platform starts running attacks
  (Round 2 forward), every action is traced and every cost is
  attributed. Dashboard surfaces grow as the platform produces
  new data; the rule is that nothing the platform does is
  invisible to the user.
- **Keeping the threat model honest.** When a round teaches us
  something new about the target — a defense that holds or
  doesn't, an attack surface we hadn't catalogued — the threat
  model is updated. It's a living document, not a snapshot.

### Out of scope for this roadmap

These are deliberate post-roadmap items. Surfacing them here
prevents scope creep into earlier rounds.

- **White-hat mode**, the platform-as-defender's-red-team
  variant described in [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
  §7. The platform's data model leaves room for it from
  Round 1 onward, but its activation comes later.
- **Multi-tenant deployments.** One CATS instance serving
  multiple teams with isolated target sets.
- **Dashboard polish** beyond the functional minimum each round
  requires — fancy charts, custom views, heat maps.
- **Multiple judges voting on findings.** Held back until
  real evidence shows the single-judge approach drifts.
- **Cost-optimization work** for very large run scales —
  alternate model-provider arrangements, dedicated inference
  capacity. Worth doing when CATS is running enough volume to
  justify the engineering investment; not now.

### Round template

Every round below uses the same shape:

- **Goal** — one sentence
- **Outcome** — what the user can do after this round
- **Scope** — what is and isn't in this round
- **Definition of done** — the round-specific gates (in addition
  to the global DoD)
- **Risks & blockers** — what could derail this round
- **Tasks** *(builder fills in as they go)*
- **Decisions** *(builder records key calls and their rationale)*
- **Retrospective** *(builder records what went well, what didn't,
  what to do differently next round)*

---

## Round 1 — Foundation

**Goal.** Give a user somewhere to log in, somewhere to register
the targets they want CATS to test, confidence that the platform
can reach the external services it depends on, and a deployed
URL where the platform actually lives — with the pipelines in
place that will carry every later round to that URL.

**Outcome.** A user can:

1. Sign in with a role that determines what they can do.
2. Register a new target (a deployed Co-Pilot URL or a local
   docker version of it), edit it, and delete it.
3. See the list of registered targets and which environment each
   one lives in.
4. See an audit trail showing who did what, when.
5. Run a one-command health check and get a clear yes/no answer
   on whether CATS can reach its model provider, its trace sink,
   and its own data store.
6. Open the deployed CATS dashboard in a browser at
   **`https://cats.biograph.dev`** — not just localhost — and
   trust that pushing changes to the main branch lands them
   there automatically.
7. See the status of the most recent automated check and the
   most recent deploy at a glance, so a red build or a failed
   deploy isn't a silent failure.

**Scope.**

In:
- Authentication, roles, and audit visibility for those roles
- The "Project" concept (the unit CATS tests against) — create,
  edit, list, delete; tag with environment; mark as runnable or
  not
- An always-on, append-only record of who did what
- Reachability checks against every external service the
  platform depends on, surfaced as a one-shot operational
  command
- A minimal, functional dashboard that shows the above to the
  right roles
- A working deployment: CATS runs on the same Digital Ocean
  droplet as the Co-Pilot, as another container behind the
  host's existing Caddy reverse proxy, reachable from the
  outside at `https://cats.biograph.dev`. Dashboard, health
  check, and CRUD are all usable from outside the host.
- A working pipeline: every change to the main branch runs the
  platform's quality checks, and a green pipeline ships the
  build to the deployed URL without a human pushing a button
- Visibility into both pipelines (build status, deploy status,
  most-recent-deploy timestamp) reachable from the dashboard
- A documented, tested rollback path: if a deploy ships a bad
  build, an operator can revert to the previous good build with
  a single, well-known command

Out:
- Any agent behavior — no campaigns, no attacks, no findings
- Any view of findings or attack history
- Dashboard styling beyond what's needed to demonstrate the
  surfaces above
- Blue/green or zero-downtime deploy strategies — a brief
  restart window on each deploy is acceptable for this round

**Definition of done (in addition to global DoD).**

- [ ] A new engineer can follow the README and register their
      first target end-to-end in well under ten minutes.
- [ ] At least one real target — the deployed Co-Pilot — is
      registered and visible in the dashboard.
- [ ] Performing any user action (sign-in, create, edit, delete)
      produces an audit-log entry visible in the dashboard.
- [ ] A user with the wrong role cannot perform a privileged
      action, and the dashboard makes that obvious rather than
      silently swallowing the attempt.
- [ ] The health check accurately reports green when everything
      is wired and red (with which dependency is failing) when
      it isn't.
- [ ] The deployed CATS dashboard is reachable from outside
      the host at `https://cats.biograph.dev`, with the
      certificate served by the host's existing Caddy proxy.
- [ ] A change merged to the main branch reaches that URL
      automatically — no manual SSH, no manual scripts.
- [ ] If a build fails its checks, it does not deploy, and the
      dashboard shows the failure.
- [ ] The rollback path has been rehearsed at least once
      against a deliberately bad build, and the time-to-rollback
      is documented in the README.
- [ ] CATS' deploys do not disrupt the Co-Pilot running on the
      same host — verified by leaving the Co-Pilot under light
      synthetic load during a CATS deploy.

**Risks & blockers.**

- **External service access.** We need accounts and budget on
  every external dependency before downstream rounds can use
  them. Resolve early in this round, not later.
- **Scope creep on auth.** Identity is easy to over-engineer.
  The bar is "the right roles can do the right things and the
  audit log shows it" — not a full identity platform.
- **The deployed target's readiness.** This round is the first
  time CATS tries to register the live Co-Pilot. If the
  Co-Pilot's URL or authentication contract isn't pinned down
  before this round starts, the round can't complete.
- **Sharing the host with the Co-Pilot.** CATS deploys onto the
  same Digital Ocean droplet, running as another Docker service
  behind the host's existing Caddy reverse proxy. Resource
  contention, port collisions, and the risk of a CATS-side
  incident affecting the Co-Pilot are all real. Coordinate the
  Caddy config change for `cats.biograph.dev` and the resource
  envelope (CPU, memory, disk) with whoever owns the host
  before the round starts.
- **DNS for `cats.biograph.dev`.** The subdomain has to exist
  and point at the droplet before the round can satisfy its
  externally-reachable outcome. Whoever owns the `biograph.dev`
  zone has to add the record; verify this is a phone call
  away, not a procurement ticket away.
- **Secrets in the deploy pipeline.** The pipeline needs API
  keys, model-provider credentials, and trace-sink tokens to
  do its job. Those secrets cannot live in the repo or in
  build logs. Setting up secret storage that the pipeline can
  read but the public artifact cannot is a real piece of work
  and tends to be underestimated.
- **First-deploy surprises.** Even with Caddy already handling
  TLS for the Co-Pilot, the first time CATS comes up at its own
  subdomain is the first time DNS, the new Caddy site block,
  and the new container's network all get exercised together.
  Plan for at least one round of "the deploy succeeded but
  nothing is reachable" debugging.

**Tasks.** *(builder fills in as completed)*

- [x] `users` table + Alembic migration `20260512_0003_users.py` (bcrypt
      hashes, role enum, is_active flag).
- [x] `cats/api/auth.py`: bcrypt password helpers, signed itsdangerous
      session cookie, `current_principal` / `require_user` /
      `require_role(min)` FastAPI dependencies. Replaces the scaffold stub.
- [x] `cats/db/repositories/{user_repo,project_repo,audit_repo}.py` —
      hand-written async SQL, one module per concern.
- [x] Bootstrap admin seeded from `CATS_ADMIN_EMAIL` /
      `CATS_ADMIN_PASSWORD` at app startup (lifespan handler, idempotent).
- [x] Project CRUD: `/projects` list, `/projects/new`,
      `/projects/{id}/edit`, `/projects/{id}/delete`. Operator+
      create/edit; admin delete; viewer list-only. Validates `base_url`
      and `env`.
- [x] User-management CRUD (admin-only): `/users` list/create/deactivate.
- [x] `/audit` view with actor + action filter; append-only enforced by
      the DB trigger from migration `20260511_0001`.
- [x] `cats/health/checks.py` reachability module (postgres / redis /
      openrouter / langsmith) with ok / fail / not_configured semantics.
- [x] `/health` HTML page + `/health/full` JSON endpoint + `cats health`
      CLI command (exit-code-aware).
- [x] R1 templates: `login.html`, `projects_list.html`,
      `project_form.html`, `users_list.html`, `audit.html`, `health.html`,
      `forbidden.html`. Reuse the existing `tokens.css` design system.
- [x] Auth threaded into existing pages: chrome-top now shows role,
      email, sign-out; the `/` route redirects to `/login` when
      unauthenticated.
- [x] `403`s render the `forbidden.html` page with the failed-role
      message (visible, not silent). HTML `401`s redirect to `/login`;
      JSON 401s stay JSON.
- [x] Build-SHA + pipeline link in chrome-top
      (`CATS_BUILD_SHA` / `CATS_GITLAB_PIPELINE_URL` env, set by the
      deploy job).
- [x] Unit tests: bcrypt round-trip, role-rank ordering, session-token
      round-trip + tamper-rejection, healthcheck branches (ok / fail /
      not_configured) for openrouter and langsmith.
- [x] Integration tests against real Postgres: login flow, project CRUD
      with role gating across operator + viewer + admin, audit-log
      writes after each mutation, healthcheck endpoint shape + auth gate.
- [x] `.gitlab-ci.yml`: `lint` (ruff + mypy strict) → `test-unit` →
      `deploy` (only on `main`, shell runner on the droplet, in-place
      `git pull` + `docker compose up -d --build`). Manual `rollback`
      job that takes a `ROLLBACK_SHA` variable.
- [x] `docs/DEPLOY.md` — Caddy site block snippet, GitLab variable
      list, rehearsed rollback path with measured time, post-deploy
      verification checklist.
- [x] `README.md` — under-10-minute walkthrough from clone to first
      registered project to first audit-log entry.
- [x] `make lint` clean: ruff check + ruff format --check + mypy strict
      across 98 source files; 40 tests passing (28 unit + 12 integration).
- [x] `.env.example` updated with `CATS_ADMIN_*`, `CATS_SESSION_SECRET`,
      build-SHA env hints.

**Decisions.** *(builder records as made — preserve rationale, not just outcome)*

- **Auth = seeded admin + bcrypt + signed cookie, not OIDC.** OIDC would
  blow the round budget on identity infra the round explicitly warns
  against. Bcrypt + itsdangerous is real enough to make the audit log
  honest, replaceable later without changing call sites
  (`current_principal` is the only entry point routes use).
- **Admin bootstraps from env, then admin creates other users in the
  dashboard.** Picked over "all four roles in env" so the role gate is
  *demoable* (admin can create a viewer; the viewer hits a 403 page)
  rather than a code-only contract.
- **Existing R2+ index.html stays intact; R1 adds new pages alongside.**
  The dashboard panels for campaigns / findings render empty states
  honestly. Throwing them away to "stay R1-pure" would lose useful
  scaffold the next round will need anyway.
- **Healthcheck split: liveness `/healthz` stays open; full
  `/health/full` is auth-gated.** The full check exposes which provider
  keys are set — meaningful info — so it sits behind the session cookie.
  Liveness has to be unauthenticated for container orchestrators to use
  it.
- **`B008` ignored under `src/cats/api/**` only.** FastAPI's
  `Depends(...)` in argument defaults is the dependency-injection idiom;
  the lint rule is wrong for this package, not the code.
- **GitLab CI shell-executor on the droplet itself.** The runner *is*
  the deploy host, so `git reset --hard $SHA && docker compose up -d
  --build` in place is the simplest correct answer. No registry, no
  SSH, no remote build. Brief restart window per the round's accepted
  scope.
- **Rollback = manual GitLab job + documented manual SSH path.** Two
  paths because path A depends on GitLab being up; path B works when it
  isn't.
- **`audit_log` writes go through `audit_repo.write_audit()`, not a
  decorator.** A decorator would be cleaner across many routes but
  hides that actor + payload shape differs per action; explicit calls
  are easier to read in the route and easier to test.
- **`aclose` over `close` for redis 5.x.** redis pushes toward `aclose`;
  types-redis lags. `# type: ignore[attr-defined]` on that one line is
  the smallest correct response and avoids the deprecation warning that
  `close` would carry forever.
- **CSRF: relying on `samesite=lax` for R1; no token.** All mutating
  POSTs require a session cookie set with `samesite=lax`, which blocks
  cross-site form submits and is the de-facto floor for HTMX-style
  apps. Adding a real CSRF token + double-submit pattern is deferred
  to R2 alongside the campaign-fire endpoint, where the blast radius
  rises sharply (an attack against a live target). Logged here so the
  next builder doesn't assume the gap is invisible.

**Retrospective.** *(builder fills in after R1 ships)*

- **What went well.**
  - The R2+ scaffold left in `src/cats/api/templates/index.html` and the
    `tokens.css` design system meant new R1 pages (login, projects,
    audit, health, users, forbidden) dropped in without writing any
    new CSS. Decision to keep the existing index intact paid off.
  - `current_principal` / `require_user` / `require_role(min)` as a
    three-tier dependency chain made route-by-route gating a one-liner
    and the integration tests trivial to write — operator vs viewer vs
    admin behaviors are six lines of test each.
  - Integration tests against the live Postgres compose service
    (rather than mocked sessions) caught two real bugs: `_engine` global
    cache binding to the wrong event loop, and the 401 handler
    re-raising instead of returning JSON. Both were silent in unit
    tests; both surfaced immediately under httpx + ASGI.
  - The separate-agent self-review caught three things the builder
    didn't notice: a docstring lying about behavior, a defense-in-depth
    gap in `hash_password`, and an undocumented CSRF posture. None
    were blocking; all were trivially fixable. Worth the round trip.

- **What didn't.**
  - `pytest-asyncio` event-loop scoping cost ~30 minutes of confusion
    before the per-test engine pattern clicked. Worth a `tests/README.md`
    note for the next builder.
  - The `cats.config.settings` global captured at import time means
    tests have to monkeypatch the *module attribute* rather than
    `os.environ` + `_load.cache_clear()`. Tripped once; documented in
    the test file, but a `Settings.refresh()` classmethod or a
    DI-via-dependency pattern would be cleaner long-term.
  - `Depends(...)` in argument defaults trips ruff `B008` everywhere;
    the per-file ignore is fine but the noise during early development
    was distracting. Should have set the ignore at scaffold time.
  - The `_http_exception_handler` had to be added late because the
    default FastAPI handler doesn't redirect HTML 401s — only realised
    after the integration test for `/health/full` blew up.

- **What to change for R2.**
  - Round 2 brings the campaign-fire endpoint, which has real blast
    radius. The R1 CSRF gap (samesite=lax cookie only) needs to close
    before that endpoint goes live — add a double-submit token or move
    to header-based POST and reject form-encoded.
  - Hide the `cats.config.settings` import-time global behind a
    `Depends(get_settings)` pattern so tests don't have to monkeypatch
    a module attribute.
  - Add a `tests/README.md` documenting the per-test engine pattern
    and the `_load.cache_clear()` / module-attribute monkeypatch dance.
    The next builder should not have to relearn this.
  - Wire deploy + lint + test-unit jobs against an actual GitLab
    project (the YAML is in place; the project + runner registration
    is a one-time R1 follow-up).
  - Consider replacing the per-route `_chrome_ctx(principal)` helper
    with a Jinja context processor so future pages don't have to
    remember to pass it.

---

## Round 2 — First end-to-end attack against the live target

**Goal.** Make CATS *do* the thing it exists to do: take a single
known attack technique, run it against the live target, evaluate
whether it worked, and produce a vulnerability report — with
every agent role from the architecture in place to play its
part. After this round, the platform is the platform.

**Outcome.** A user can:

1. Start a campaign against a registered target from the
   command line, picking one attack category.
2. Watch the campaign unfold live in the dashboard: see the
   plan being made, see the attack being generated, see it
   reach the target, see the verdict come back, see a finding
   appear.
3. Open the finding in the dashboard and see the attack, the
   target's response, the judge's verdict, and a deep-link out
   to the trace of every LLM call that produced it.
4. See how much each agent contributed to the cost of the
   campaign.

**Scope.**

In:
- A working end-to-end pipeline against the live target for a
  single, well-defined attack technique
- All agent roles present and exercising their basic job — even
  the ones that don't have rich behavior yet (e.g. the Mutator
  is present and visible even if it just passes the attack
  through unchanged this round)
- A live campaign view in the dashboard
- A findings list and a per-finding detail view
- Per-agent cost visibility on each campaign

Out:
- Multiple attack techniques (later rounds expand category by
  category)
- Real adaptive planning — the orchestrator just runs the
  technique the user named, end of story.
  **(Note: R4 corrects this. R2 ships an orchestrator-shaped
  placeholder; the LLM-planner-with-tools that
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4 describes lands
  in R4.)**
- Real variant generation
- Smart safety filtering of the agents' output (a basic
  pattern-based safety net is enough this round)
- Approval gates on high-severity findings (later round)
- Re-running findings against new releases to verify fixes
  (later round)

**Definition of done (in addition to global DoD).**

- [ ] A campaign against the live deployed Co-Pilot produces
      one finding, end-to-end, every time.
- [ ] If the campaign is interrupted mid-run, it can be resumed
      from where it left off without re-doing completed work.
- [ ] The dashboard's campaign view updates live as the
      campaign progresses — no manual refresh.
- [ ] Every finding carries a trace deep-link that brings the
      reader to the full LLM-call history that produced it.
- [ ] The platform records per-agent cost on every campaign,
      and that cost shows up in the dashboard.
- [ ] An obviously unsafe payload generated by an agent is
      caught by the safety net before it reaches the live
      target — there is a test that demonstrates this.

**Risks & blockers.**

- **External-model availability.** This is the first round that
  actually depends on the chosen LLM providers being up,
  responsive, and within budget for the operator's account.
  Validate at the start of the round.
- **Live target behavior under attack.** This is the first round
  CATS actually attacks the deployed Co-Pilot. The Co-Pilot's
  team needs to be aware so they don't mistake the activity for
  a real incident, and rate limits / IP allow-lists need to be
  squared away.
- **Test infrastructure for agents.** Building agents that
  exercise external services without a way to run them
  deterministically in tests will eat the round. Plan for
  test-time fakes early.
- **The "one technique" discipline.** This round is one
  technique, full stop. Adding a second is what Round 3 is
  for. Resist scope creep — the value of this round is
  end-to-end shape, not attack coverage.

**Tasks.** *(builder fills in as completed; round in progress as of 2026-05-12)*

R2 is being built in two phases on the `feat/round-2-first-attack`
branch because the surface area exceeds one session's safe context
budget.

**Phase A — Foundations (committed, not yet on main):**

- [x] Migration `20260512_0004` — `projects.target_kind /
      target_username / target_password_encrypted` (Fernet-encrypted at
      rest); `attack_executions.agent_role` for per-role cost
      breakdown; `vulnerability_reports.finding_id` so multiple
      findings per run can each carry their own report.
- [x] `cats/security/crypto.py` — Fernet encryption helper keyed off
      `CATS_DATA_SECRET` (distinct from session secret).
- [x] `cats/security/csrf.py` — double-submit token + `require_csrf`
      FastAPI dependency. **Closes the R1 CSRF gap** before the
      campaign-fire endpoint goes live.
- [x] `cats/api/app.py` — `CsrfMiddleware` issues + validates token on
      every request; `cats/api/templating.py` shares one
      Jinja2Templates instance across routes with a
      `csrf_input(request)` global; every R1 form (login, logout,
      projects, users, index campaign-fire) threads the token through.
- [x] `cats/llm/client.py` — `LLMClient` Protocol + `RealLLMClient`
      (thin shim over `OpenRouterClient`) + `FakeLLMClient` for tests
      + `get_llm()` factory + `install_override()` test seam. Trace
      ID surfacing via LangSmith when tracing on, synthetic UUID
      otherwise.
- [x] `cats/agents/red_team/injection.py` — real specialist node:
      strict-JSON output, per-attack unique canary token
      (`CATS-CANARY-<hex>`), defensive canary splice-in if the model
      forgets it, fence-tolerant JSON parser.
- [x] `cats/categories/injection/red_team/system_prompt.md` — full
      prompt (replaces TODO).
- [x] `cats/categories/injection/red_team/few_shots.md` — two
      annotated examples (replaces TODO).
- [x] `cats/categories/injection/rubric/v1.md` — **locked** judge
      rubric with deterministic canary short-circuit + qualitative
      fallback. Never edited in place; future changes go to `v2.md`.
- [x] `cats/categories/injection/deterministic.py` — generalized from
      hardcoded `SMOKE-OK` to per-attack `payload["canary"]`.
- [x] `cats/agents/documentation/system_prompt.md` —
      structured-report prompt with explicit MITRE ATLAS + OWASP LLM
      tagging.
- [x] R1 integration tests updated for CSRF (`csrf_post` helper in
      `tests/integration/conftest.py`); added explicit test that a
      POST without a token returns 403.
- [x] `tests/unit/test_csrf.py` — token generation, encryption
      round-trip, garbage rejection. Locks the cookie/form/header
      names so client code doesn't drift silently.

48 unit + integration tests passing; `ruff check` + `ruff format
--check` + `mypy --strict` clean across 105 source files.

**Phase B — Wire-up (committed in `feat(round-2-wire-up)`):**

- [x] Every graph node replaced with a real implementation:
      `orchestrator` (records plan + event), `red_team_router` (calls
      injection specialist, builds Attack with canary, emits cost
      entry), `mutator` (passthrough + visible event), `output_filter`
      (quarantines + emits halted event), `target_caller` (TargetClient
      against `target_base_url`), `judge` (deterministic short-circuit
      + LLM rubric fallback), `documentation` (writes
      `Attack/AttackExecution/JudgeVerdict/Finding/VulnerabilityReport`
      rows + Markdown report + finding-promoted audit row).
- [x] Conditional edge `output_filter -> documentation` when verdict
      is `dangerous`/`attack_payload` — the live target never sees a
      quarantined payload. Integration test
      `test_filter_quarantine_short_circuits_to_documentation`
      demonstrates this end-to-end.
- [x] `cats/target/client.py` — OpenEMR login flow against
      `interface/login/login.php` → `interface/main/main_screen.php`,
      harvests `PHPSESSID` + `csrf_token_form`, POSTs to
      `agent.php?action=briefing` and walks the SSE stream into a
      single assistant text. Two modes: `copilot_proxy` (prod path) +
      `copilot_internal` (local-docker shortcut with a static bearer).
- [x] `AsyncPostgresSaver` checkpointer wired via
      `cats/graph/checkpointer.py::postgres_checkpointer` async context
      manager. The worker runs the graph inside this context for real
      runs; smoke path keeps the in-memory saver. `thread_id =
      str(run_id)` so a worker restart resumes from the last completed
      node.
- [x] `POST /campaigns` route (operator+, CSRF-protected) + `cats
      run-campaign --project-id <uuid>` CLI. Background dispatch via
      `asyncio.create_task` with strong references on a module-level
      set so the task isn't GC'd mid-run. Refuses to fire when
      `Project.allow_run_against=False`.
- [x] `/campaigns/{id}` live page: status table, cost-by-agent rollup,
      findings list, live event log subscribed to `/events/{campaign_id}`
      via HTMX SSE.
- [x] `/findings` list + `/findings/{id}` detail page. Detail page
      renders the Markdown vulnerability report, the judge summary,
      the per-execution table with `agent_role` + tokens + USD + LangSmith
      deep-link (when trace ID is real, not the synthetic `fake-…`
      placeholder).
- [x] `attack_executions.agent_role` column populated by every LLM-
      using node; per-role rollup surfaces on the campaign detail
      page.
- [x] Project form (create + edit) surfaces `target_kind` /
      `target_username` / `target_password`. Password is Fernet-encrypted
      via `cats.security.crypto.encrypt` before storage; the form never
      displays the stored value back to the user.
- [x] Graph state extended (`CampaignState`) to carry target config,
      per-attack canary, per-agent cost entries, last trace ID,
      verdict rationale + evidence + rubric_version_id — so the
      Documentation node persists everything atomically without a
      second DB pass per node.
- [x] LangGraph rubric registry: `cats/db/repositories/rubric_repo.py`
      reads the locked rubric file off disk and idempotently records
      it on first use; `judge_verdicts.rubric_version_id` references
      the row so historical comparisons survive rubric evolution.
- [x] Smoke CLI simplified — was double-writing Attack/Execution/
      Verdict/Finding rows because the R1 path lived in the CLI and
      R2 moved persistence into the graph. Now CLI just creates the
      Project/Campaign/Run skeleton and invokes the worker.
- [x] Integration tests: 5 e2e cases in `test_campaign_e2e.py`
      including the full pass path, audit-log writes on promotion,
      `allow_run_against=False` gating, unknown-category gating, and
      filter-quarantine short-circuit. Uses `FakeLLMClient` +
      `httpx.MockTransport` so tests stay offline and deterministic.
- [x] Unit tests for the specialist (raw/fenced/prose-wrapped JSON,
      canary substitute, canary splice-in defensive fallback), judge
      (deterministic + LLM rubric branches), output filter quarantine
      (SSN/MRN/powershell shapes), and the SSE assembly helper.
- [x] `tests/README.md` — documents per-test engine pattern, CSRF
      helper, `cats.config.settings` monkeypatch dance, FakeLLM
      `install_override` pattern, the `live_target` marker. R1's
      retrospective asked for this.

**75 tests passing** (48 from Phase A + 27 new). `ruff check` + `ruff
format --check` + `mypy --strict` clean across 110+ source files.

**Decisions.** *(builder records as made — preserve rationale, not just outcome)*

- **Two-phase ship.** R2's surface area is genuinely larger than R1 —
  closing the CSRF gap *and* wiring all seven agent roles *and*
  exposing a live dashboard *and* swapping the checkpointer was too
  much for one session at safe quality. Splitting at the seam between
  "platform plumbing that every later round needs" (Phase A) and
  "the inner campaign loop" (Phase B) keeps both halves reviewable.
- **CSRF: shared Jinja2Templates instance with a `csrf_input(request)`
  Jinja global.** R1's pattern of each route module instantiating its
  own `Jinja2Templates(...)` made global env extensions impossible.
  Moving to `cats/api/templating.py` is the smallest surface-area fix
  and lands the Jinja-context-processor R1's retro asked for.
- **`CATS_DATA_SECRET` separate from `CATS_SESSION_SECRET`.** Two
  different rotation surfaces: session-cookie rotation invalidates
  sessions; data-at-rest rotation needs a re-encrypt step. Keeping
  them distinct is the cheap upfront move.
- **Per-attack canary token, not a category-wide constant.** A
  category-wide canary (`SMOKE-OK`) lets the target memorize and
  refuse it. `CATS-CANARY-<hex>` is unique per attack, so the judge
  can't be sandbagged by token-specific safety training. Locked into
  `rubric/v1.md` so historical comparisons stay honest.
- **`LLMClient` Protocol + `install_override()` test seam.** Picked
  over a `Depends(get_llm)` DI pattern because the graph nodes don't
  live behind FastAPI — they're invoked by LangGraph from a worker
  context. A module-level override is the smallest hook that keeps
  prod paths untouched.
- **Deterministic check has priority over LLM rubric.** Codified in
  `rubric/v1.md` as the explicit short-circuit. Halves judge cost and
  removes one source of drift.

Additional decisions made during Phase B:

- **Target attack surface = the OpenEMR PHP proxy, not the internal
  `/v1/agent/*`.** The internal port isn't reachable in prod and a
  realistic attacker would come through the same browser session a
  clinician uses. R2 ships `target_kind=copilot_proxy` as the default;
  `copilot_internal` is a local-dev escape hatch documented in the
  TargetClient.
- **OpenEMR credentials encrypted at rest, never displayed back.**
  Stored under `projects.target_password_encrypted`, Fernet-encrypted.
  The project edit form treats an empty `target_password` field as
  "keep existing"; only an explicit new password rotates the stored
  value. Audit-log entries record the *fact* of a rotation, not the
  password.
- **Background dispatch via `asyncio.create_task` with a module-level
  strong-reference set.** Picked over a real task queue (Celery/Arq)
  because the round explicitly scopes to a single technique and one
  attack per campaign; a task queue would add infrastructure that
  doesn't pay back until Round 6+ multi-attack campaigns. The strong-
  ref set (`_BG_TASKS`) is the documented fix for RUF006.
- **Documentation node owns persistence.** Earlier (R1) scaffold had
  the smoke CLI doing the writes after the graph returned, which
  meant any new graph user had to remember to add the persistence
  step. R2 centralizes Attack/Execution/Verdict/Finding/Report
  inserts in the last node. Single source of truth; idempotent on
  signature so checkpoint replay doesn't duplicate rows.
- **Mutator stays a passthrough but emits a visible event.** Round
  scope explicitly defers real variant generation to R3; the role is
  present in the graph and visible in the live event log so the
  dashboard shows the seven-role topology rather than skipping a step
  silently.
- **TargetClient assembles SSE text by concatenating every `content`
  / `text` / `delta` / `message` field.** The Co-Pilot's
  `briefingStream.encodeStreamEvent` emits typed events; R2 doesn't
  honor section semantics yet because the Judge only needs *something*
  to look at, and "everything the model said" beats "the first chunk"
  every time. R4 (indirect injection) may need section-aware handling
  for citations.

**Retrospective.**

- **What went well.**
  - The R1 retrospective's call-out to ship a `tests/README.md`
    paid off immediately: integration tests for R2 use the
    `csrf_post` helper and the per-test engine pattern without
    re-deriving them, and the README is the place I documented the
    `install_override` + `MockTransport` patterns so R3 won't have
    to either.
  - Locking the rubric file (`rubric/v1.md`) at Phase A and
    persisting `rubric_version_id` on every `judge_verdict` row paid
    off when wiring the judge node — there was no "should I edit the
    rubric to make this test pass" question, because editing was
    already off the table.
  - Splitting R2 into Phase A (foundations) + Phase B (wire-up) on
    one branch let the first commit be a coherent unit of platform
    plumbing reviewable on its own; the second commit is the
    inner-loop wiring that consumes Phase A's abstractions. Two
    smaller PRs would be even cleaner — the worktree leaves that
    option open.
  - Per-attack canary tokens (`CATS-CANARY-<hex>`) turned out to be
    the single most-load-bearing decision: the integration test
    works *because* the canary is fresh per attack and the mock
    transport can sniff it out of the request and echo it back.
    Category-wide canaries (R1 scaffold style) would have made the
    e2e test untestable without coordinating canary state between
    nodes.
  - `FakeLLMClient` + `install_override` together with `httpx.MockTransport`
    let the e2e test exercise the entire graph offline in under 4
    seconds. No marker-gated "this needs OpenRouter" awkwardness.

- **What didn't.**
  - The first version of `upsert_attack` used `INSERT … ON CONFLICT
    (category, signature)` against indexes that *weren't* unique
    constraints — Postgres rejected the statement at run time, not
    at definition time. Caught only by the e2e test. Either add a
    unique constraint to the table or don't use `ON CONFLICT`. R2
    took the second path; if R3 hits a real dedup-under-load scenario
    we may revisit.
  - Patching `httpx.AsyncClient` is fragile — the patch lives at
    the import path `cats.target.client.httpx.AsyncClient`, but if
    a future TargetClient method opens the client a different way
    (e.g. via a session pool) the patch becomes a no-op silently.
    Worth wrapping the client construction in a tiny factory
    function that tests can monkey-patch by name.
  - The smoke path's double-persistence-bug (R1 CLI + R2 graph both
    wrote Attack/Execution rows) didn't surface in tests until I
    actually ran `cats smoke` — there was no smoke test in the
    suite. R3 should add `tests/integration/test_smoke.py` that
    drives `run_smoke` end-to-end so this kind of regression bites
    in CI, not in someone's local terminal.
  - `cats.config.settings` is still a module-level import-time
    singleton — R1's retro called it out, R2 worked around it again
    with module-attribute monkeypatching, R3 should finally move it
    behind a DI pattern.
  - `langgraph.checkpoint.serde.jsonplus` emits a pending-deprecation
    warning about `allowed_objects` defaulting in a future version.
    R3 should pin an explicit value rather than ignore the warning.

- **What to change for R3.**
  - **Move `cats.config.settings` behind a DI factory.** Two rounds in
    a row have wanted this; stop putting it off. `Depends(get_settings)`
    for routes + a module-level `set_settings_for_test` for nodes.
  - **Add a smoke-path integration test.** `make smoke` is the
    documented onboarding command and isn't covered by the suite.
    `tests/integration/test_smoke.py` taking ~3 seconds is the right
    cost.
  - **Refactor the TargetClient SSE walk into its own pure-function
    module** before the briefing-action-specific quirks pile up. R4
    will need section-aware handling for citations; R3's prep should
    extract the parser cleanly first.
  - **Wrap LLM-using node calls in a small `with_cost(state, role)`
    helper.** R2's nodes each manually push a `AgentCostEntry`,
    track tokens, and add to `state.budget_consumed_usd`. Three
    copies of the same code; a helper closes the door on someone
    forgetting one of them.
  - **Real Mutator + multi-technique inner loop is R3's actual
    work.** The conditional-edge plumbing is already there; R3 only
    needs to wire the partial-success-feedback loop.
  - **Pin `allowed_objects` on the langgraph serializer.** Silences a
    deprecation; preempts a future breakage.

---

## Round 3 — Prompt Injection, in depth

**Goal.** Take the highest-priority attack category from the
threat model and exercise it for real. Up to this point CATS has
proven it can run one attack; now it learns to run a *family* of
related attacks, iterate on the ones that show promise, and
produce a vulnerability report a security engineer could act on.

**Outcome.** A user can:

1. Run a campaign in the prompt-injection category and see the
   platform attempt several distinct techniques in one run —
   not just one technique repeated.
2. Watch the platform automatically iterate when an attack
   partially succeeds: it produces variants of the
   near-success, looking for one that fully breaks through.
3. Open any finding and see it labeled with the industry-standard
   classifications that a CISO or external auditor would
   recognize.
4. Trust that the judge's verdicts are consistent: there is a
   nightly accuracy check against a hand-labeled answer key, and
   the build fails if the judge drifts below the agreed bar.
5. Read at least one polished vulnerability report produced by
   CATS, suitable for handing to the Co-Pilot's owning team.

**Scope.**

In:
- Several distinct direct-injection techniques run in one
  campaign — the platform picks among them, not just the user.
- Real variant generation when an attack partially succeeds.
- An evaluation regime for the judge: a versioned answer key,
  a nightly check against it, and an accuracy threshold the
  build enforces.
- Industry-standard labels (the relevant adversarial AI and
  LLM-security taxonomies) on every finding.
- The first polished, hand-reviewed vulnerability report.

Out:
- Attacks that arrive through uploaded documents (next round).
- Other attack categories (Exfil, ToolAbuse — their own rounds).
- The platform deciding what category to test on its own (later
  round; this round, the user still names the category).

**Definition of done (in addition to global DoD).**

- [ ] A single campaign visibly exercises multiple distinct
      techniques and visibly produces variants of partial
      successes.
- [ ] The judge has a locked, versioned answer key for this
      category, and the nightly accuracy check passes against
      a stated threshold.
- [ ] If the answer key needs to change, the change is a *new
      version* of the key — the old version stays intact for
      historical comparison.
- [ ] At least one finished, human-readable vulnerability
      report exists in the repo for a finding from this round.
- [ ] A non-author reading the report could reproduce the
      finding from what's written there.

**Risks & blockers.**

- **The answer key is hand-built.** Labeling enough examples to
  judge the judge takes real human effort, and the labeler's
  blind spots become the platform's blind spots. Get a second
  pair of eyes on a portion of the labels.
- **Cost discipline on the nightly check.** Running the judge
  against an answer key every night is small per run but grows
  with the key. Cap the spend explicitly.
- **Vendor-side model drift.** If the model behind the judge
  changes subtly between today and tomorrow, accuracy can shift
  without code changes. Pin where the platform allows it and
  alert on drift.

**Tasks.** *(builder fills in as completed)*

R3 paid down four R2-retro items as the foundation, then built the
multi-technique injection family on top. Two natural commit seams: the
retro-paydown + plumbing, then the techniques + mutator + evals + report.

**R2-retro paydown (Phase A):**

- [x] `cats.config.settings` DI factory — `get_settings()` + `set_settings_for_test()`
      + `reset_settings_cache()` accessors in `src/cats/config.py`. The module-level
      `settings` singleton stays for R1/R2 import-compat; new code uses the
      accessors. Doc'd in `tests/README.md`. Five new unit tests cover the seam.
- [x] `with_cost(state, role, llm_result)` helper at `src/cats/agents/common/cost.py`,
      retrofitted into judge / red_team_router / documentation nodes.
      Three new unit tests; collapses three copies of the
      `AgentCostEntry` boilerplate.
- [x] Smoke-path integration test at `tests/integration/test_smoke.py`. Covers
      run_smoke end-to-end + idempotency under repeat invocation. ~1s, the
      gap R2 retro flagged.
- [x] Suppress the `langgraph.checkpoint.serde.jsonplus` `allowed_objects`
      pending-deprecation warning. Filter installed in `cats/__init__.py` so
      it runs before any transitive langgraph import; `pyproject.toml`
      `filterwarnings` covers pytest collection-time noise.
- [x] Per-technique taxonomy lookup — `src/cats/categories/injection/taxonomy.toml`
      + `src/cats/categories/taxonomy.py::lookup()`. Replaces the
      `if category == "injection"` hardcode in the documentation node so
      every finding can carry the most-specific ATLAS/OWASP label its
      technique earns. Six new unit tests, including a sanity check that
      every R3 technique resolves to non-None IDs.

**Multi-technique injection (Phase B):**

- [x] `src/cats/agents/red_team/injection/` is now a package. Shared scaffolding
      (canary, prompt loading, JSON parsing, proposal assembly) lives in
      `base.py`. Each technique gets its own thin module: `ignore_previous.py`,
      `policy_puppetry.py`, `role_override.py`, `system_prompt_leak.py`,
      `encoded_payload.py`. Public `propose()` is preserved for R2-compat.
- [x] `dispatcher.py` with `pick_technique(state)` (rotation policy: walk the
      rotation, skip already-attempted; round-robin once exhausted; explicit
      `state.selected_technique` honored when set). `propose_technique(...)`
      delegates to the named specialist. Ten new unit tests.
- [x] Four new locked system_prompt.md + few_shots.md files for
      `policy_puppetry`, `role_override`, `system_prompt_leak`, `encoded_payload`
      under `src/cats/categories/injection/red_team/<technique>/`. Each prompt
      ships with a YAML frontmatter `technique:` line so a fake-LLM in tests
      can route by sniffing the prompt.
- [x] Mutator variant generator at `src/cats/agents/mutator/strategies.py`.
      LLM-driven primary path (DeepSeek V3.2 family per ARCHITECTURE.md §4.1
      via `AgentRole = "mutator"`); deterministic fallback rotates among
      three transforms (`task_redirect`, `boundary_tighten`, `encoding_shift`)
      so the loop makes forward progress when the LLM fails. Defense-in-depth
      canary splice-in if the variant drops it. Eight new unit tests.
- [x] Graph topology updated in `src/cats/graph/build.py`: judge → mutator
      conditional edge fires on `partial` verdicts when
      `consecutive_partial_count < MAX_CONSECUTIVE_PARTIALS` (3); otherwise
      advances to documentation. `_route_after_judge()` is the routing
      function; covered by a dedicated unit test.
- [x] Mutator node rewritten to invoke `generate_variant()` in variant mode,
      splice the rewritten message into `pending_attack_payload`, append
      `mutator` cost via `with_cost`, and clear the verdict so the next
      target_caller + judge cycle sees a fresh attack.
- [x] `CampaignState` extended: `techniques_attempted: list[str]`,
      `consecutive_partial_count: int`, `current_outer_iteration: int`.
- [x] Multi-technique outer loop: `run_campaign_multi_technique()` in
      `cats/workers/campaign_worker.py` issues `MIN_TECHNIQUES_PER_CAMPAIGN`
      (3) consecutive Runs against one Campaign, each pinned to a different
      technique from the dispatcher's rotation. CLI (`cats run-campaign`) +
      API (`POST /campaigns`) route through it.
- [x] `tests/integration/test_multi_technique_campaign.py` — drives a full
      campaign with FakeLLM + MockTransport, asserts ≥3 distinct techniques
      attempted + every Run fires its attack. **Plus** a load-bearing
      partial→mutator→variant e2e test that patches the deterministic
      judge to force the LLM-judge branch, drives ``run_one`` end-to-end,
      and asserts the mutator actually rewrote the user message between
      target hits. A companion unit test pins the judge→mutator routing
      decision in isolation.

**Evals + nightly:**

- [x] Answer key v1 at `evals/injection/answer_key/v1/cases.jsonl` — 30
      hand-labeled `(attack, response, expected_verdict)` triples covering
      all five R3 techniques, with `label_rationale` per row. README ships
      the labeling guide so a second reviewer can sanity-check.
- [x] `evals/runner.py` runs the Judge against the answer key, emits an
      accuracy figure + per-technique confusion table + per-case failure
      report. Exits non-zero below the configured accuracy threshold
      (env-driven via `CATS_EVAL_ACCURACY_THRESHOLD`, default 0.85).
      Supports `--deterministic-only` for the fast CI subset and
      `--budget-usd` as a soft cap.
- [x] `tests/integration/test_judge_accuracy.py` — fast CI subset asserting
      the deterministic Judge resolves every pass/fail case correctly (all
      five partial cases route to the LLM judge under the full nightly
      run).
- [x] `.gitlab-ci.yml` `judge-accuracy-nightly` stage gated on
      `CATS_NIGHTLY_EVAL == "1"` (set in the GitLab schedule's variables).
      Threshold + budget are env-overridable.

**Polished vuln report:**

- [x] `findings/R3_policy_puppetry_canary_echo.TEMPLATE.md` — a complete
      polished report shape with attack payload, response, reproduction
      command, mitigations, ATLAS/OWASP labels, cross-reference index.
      Renamed with the `TEMPLATE` suffix per self-review feedback so a
      reader cannot confuse the synthetic shape for a confirmed live
      finding. §7 documents the operator's post-merge live-fire step:
      if the behavior reproduces, copy the file dropping the suffix and
      replace §3's example response + add a real LangSmith trace ID.
      The live-target fire is the single open R3 task on this checklist.

**Test count:** **114 passing** (89 unit + 25 integration) — up from R2's
75. `ruff check`, `ruff format --check`, and `mypy --strict` clean across
125 source files.

**Decisions.** *(builder records as made)*

- **Five techniques, not four.** Kept `encoded_payload` rather than dropping
  to four to test the input-normalization layer specifically. It's the only
  R3 technique that exercises filter/normalization weaknesses rather than
  semantic-instruction confusion. Per the W3 research the Co-Pilot's
  defense rating here is genuinely low; ducking it would have left a real
  gap.
- **Multi-technique = multiple Runs per Campaign, not multiple attacks
  per Run.** The data model already supports multiple Runs per Campaign
  cleanly (R2's dashboard pages `list_runs_for_campaign`). Looping inside
  the graph would have meant splitting the documentation node into
  per-attack-persist + finish-run halves, which is invasive. The per-Run
  approach reuses every existing accounting + audit path and the dashboard
  shows the run sequence naturally. R6's adaptive planning may revisit;
  for R3 the simpler shape is the right call.
- **`MAX_CONSECUTIVE_PARTIALS = 3`.** Three iterations gives the Mutator a
  real chance without letting one stubborn target eat the budget. The
  three deterministic transforms (`task_redirect`, `boundary_tighten`,
  `encoding_shift`) are also exactly three, so each partial gets a
  qualitatively different fallback. Revisit when real campaigns produce
  evidence on which cap is right.
- **Per-technique prompts in a sub-directory, not a single growing prompt.**
  R2's monolithic `system_prompt.md` listed four techniques as a `technique:
  <one of: …>` enum and would have grown unwieldy at five+. Per-technique
  directories let each prompt evolve independently and let the answer key
  cite a specific specialist's prompt when a label dispute arises.
- **YAML frontmatter `technique:` line is load-bearing for tests.** The fake
  LLM in `tests/integration/test_multi_technique_campaign.py` sniffs the
  system prompt's frontmatter to route to the right responder. Without
  this, the test can't distinguish which specialist was called. Future
  prompts must keep the frontmatter line.
- **Settings DI is additive, not a flag-day refactor.** The module-level
  `settings` singleton remains because 19 source files import it. New
  code uses `get_settings()` / `set_settings_for_test()`; old code keeps
  working. Sweeping every import was explicit non-goal in the planning
  questions to avoid bloating R3.
- **The `allowed_objects` warning is filtered, not fixed.** The deprecation
  fires from `langchain_core.load.load.Reviver()` constructed inside
  `langgraph.checkpoint.serde.jsonplus` at module-import time. No caller
  code can pass a value. R3 ships filters at three layers (cats/__init__.py
  runtime, pyproject.toml pytest collection, cats/logging.py app start)
  so the next dependency-version bump can lift the suppression cleanly.
- **Mutator deterministic fallback is intentional, not just a safety net.**
  Tests use the fallback path heavily because `FakeLLMClient` has no
  `mutator` responder by default. The fallback being a first-class
  citizen means the loop never stalls, and the answer-key labels reflect
  what a real DeepSeek call *would* produce shape-wise.
- **The R3 polished vuln report ships as a template populated with one
  representative finding from the fake-LLM run.** Firing the live campaign
  from the build pipeline (or from the worktree) would mean attacking the
  deployed Co-Pilot from a non-operator context. The report's §7 names
  this explicitly and points the operator at the replay command for the
  canonical reproduction.

**Retrospective.**

- **What went well.**
  - **R2-retro paydown landed first paid off in every subsequent file.**
    The new `with_cost` helper, the taxonomy lookup, and the smoke test
    each got reused by R3 code immediately — there was no temptation to
    "skip it for now," because skipping it would have meant writing
    a duplicate inline. Doing the debt sweep before any technique work
    flipped the cost-of-cleanup ratio.
  - **Per-technique sub-packages were the right scope unit.** Each
    specialist is ~25 lines; the shared scaffolding in `base.py` is the
    only thing that needs to evolve as the protocol matures. Adding the
    fifth technique (`encoded_payload`) took ~10 minutes from prompt
    file to passing unit test — that's the cost level future rounds
    should hit.
  - **The deterministic mutator fallback was the difference between a
    flaky integration test and a stable one.** Eight unit tests for the
    mutator strategies all run offline because the fallback path is the
    default when no LLM responder is registered. The R2 retro's note
    about "the e2e test works *because* the canary is fresh per attack"
    has a direct R3 analogue: "the mutator tests work *because* the
    fallback is intentional."
  - **Self-review caught two real DoD gaps.** The first reviewer
    pointed out that the multi-technique e2e didn't actually exercise
    the partial→variant cycle (deterministic judge short-circuited to
    pass) and that the polished vuln report was template-shaped but
    not labeled as such. Both were closed in one fix pass and a second
    reviewer confirmed ship-ready. The self-review step is load-bearing
    — without it, R3 would have shipped with a half-met DoD line and
    a misleading finding file.
  - **Settings DI as additive seam.** Sweeping all 19 import sites was
    not necessary and would have bloated R3. New code uses
    `get_settings()` / `set_settings_for_test()`; old code keeps
    working. Tests/README documents the pattern. Two retros in a row
    asked for this; doing it minimally was the right call.

- **What didn't.**
  - **The Orchestrator's strategic role got punted, and that is the
    load-bearing miss of R3.** [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
    §2.1 / §2.4 designates the Orchestrator as the platform's
    strategic decision-maker — an LLM-driven planner that reads
    coverage / severity / recency through a tool surface and
    authors a campaign plan a human approves before dispatch
    fires. R3 instead shipped a deterministic dispatcher walking
    a hardcoded `ROTATION` tuple in order, with the "Orchestrator"
    graph node still a no-op stub from R2. That is precisely the
    "platform is just running attacks randomly" failure mode the
    project brief calls out. R4 corrects this: the next round
    brings the real Orchestrator online, including the human-in-
    the-loop plan approval gate the brief explicitly requires.
    The R3 dispatcher becomes the *executor* of an
    Orchestrator-emitted plan rather than the *picker*.
  - **The integration test's deterministic-judge short-circuit caught
    me off guard.** I wrote the multi-technique e2e expecting partials
    to flow naturally, but the deterministic check returns
    `pass` whenever the target echoes the canary — which my fake
    target always does. Result: the variant cycle never fired in the
    first version of the test. The fix (patch `judge_deterministic` for
    one test) works but is uglier than I'd like. R4 should grow a
    proper test seam — maybe a `state.bypass_deterministic_judge` flag
    that defaults False — so future rounds can write LLM-judge-driven
    e2es without monkey-patching.
  - **The `allowed_objects` warning suppression took three tries to get
    right.** Filtering by message regex, by category name string, then
    by direct category import — each one revealed a new pytest /
    Python import-order quirk. Pytest captures warnings at collection
    time, which fires *before* `cats/__init__.py` loads. The fix
    works but the layering (cats init + pyproject.toml + cats.logging)
    is fragile under dependency-version skew. A note in
    `cats/__init__.py` explains the situation; R5 should re-check
    whether the upstream deprecation has flipped and lift the
    suppression entirely.
  - **30 partials in the answer key would be more honest.** The DoD
    test only proves the deterministic check passes on the 25 pass/fail
    cases. The 5 partial cases all rely on the LLM judge in the
    nightly. R3 ships without observing one green nightly. The judge
    accuracy threshold (0.85) is therefore an aspirational target, not
    a measured one. R4 should kick off one nightly within the first
    week and capture a baseline accuracy figure to put in the
    retrospective there.
  - **Live-target reproduction of the polished vuln report was
    deferred.** The original clarifying question had me commit to
    firing the live campaign as part of the round; in practice, firing
    against the deployed Co-Pilot from the build pipeline is a higher-
    blast-radius action than the round called for. Renaming the file
    to `.TEMPLATE.md` is honest, but it leaves a real R3 task in the
    operator's queue: fire once, confirm or correct the report,
    commit the canonical version. Capture this in R4's prep notes.
  - **The integration test's red-team responder routes by sniffing the
    system prompt's YAML frontmatter.** That works today, but it's a
    convention enforced only by every future specialist remembering
    to include `technique: <name>` in the frontmatter. A dedicated
    technique-detector field on the proposal (or a thread-local in
    the fake LLM) would be more robust.

- **What to change for R4.**
  - **R4 is now the Orchestrator round.** The original R4
    (.docx indirect injection) moved to R5; `docs/ROADMAP.md`
    reordered after the R3 retro identified the strategic-layer
    gap. R4's builder owns: real LLM-driven Orchestrator with a
    tool surface ([`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4),
    HITL plan approval gate, coverage view in the dashboard.
    R3's dispatcher gets re-shaped into the executor of an
    Orchestrator-emitted plan.
  - **Fire one nightly judge-accuracy run before R4 starts.** Capture
    the real accuracy number, the per-technique confusion table, and
    the spend. Either confirm 0.85 is hit or adjust the threshold in
    `cats.config` to match reality. This is the single most important
    R4-prep item.
  - **Fire the live deployed Co-Pilot campaign and confirm / correct
    the polished vuln report.** Either promote
    `findings/R3_policy_puppetry_canary_echo.TEMPLATE.md` to its
    un-suffixed twin with a real LangSmith trace ID, or delete it
    because the live model defends correctly.
  - **Refactor `TargetClient`'s SSE walk into a pure-function module.**
    R2's retro asked for this; R3 punted again. R5's indirect-injection
    via `.docx` needs section-aware citation handling and will trip
    over the inline parser. Extract `walk_sse_to_text(events) -> str`
    before any docx work starts.
  - **Add a `bypass_deterministic_judge: bool` test seam on
    `CampaignState`.** R3's e2e test monkey-patches the function; that
    works once but doesn't scale. A flag the test can set means
    R4 and beyond can drive LLM-judge paths without import-time
    gymnastics.
  - **Bump answer-key v2 once R5 produces .docx attacks.** v1 is
    direct-injection only. v2 should add another 30 rows covering the
    indirect-injection technique families R5 introduces. Ship `v2/`
    alongside R5's runner; keep `v1/` intact.
  - **Use a `<technique-marker>` HTML comment in specialist prompts
    instead of frontmatter sniffing.** A dedicated marker is harder
    to lose accidentally than a YAML field that prompt-engineers
    might delete during a tweak.
  - **Pin langchain-core (or whatever depends on it transitively).**
    The `allowed_objects` warning fires from a library API that's
    actively being deprecated. R5 should evaluate whether the upstream
    default has flipped and we can lift the suppression — or whether
    the API itself is gone and we have a real port to do.

---

## Round 4 — The Orchestrator decides, the operator approves, the agents truly decouple

**Goal.** Bring the platform's strategic decision-maker online
**and** complete the architectural shift from a single
LangGraph pipeline into a genuine multi-agent system. The brief
is explicit on both pieces: it requires the Orchestrator as a
real strategic layer ("without this layer, your platform is
just running attacks randomly"), and it requires a multi-agent
architecture with distinct trust boundaries and explicit
hand-off design ("a single-agent or pipeline architecture will
not satisfy this assignment ... how you design those agents,
how they communicate, how they hand off work, and how they
recover from failure are the core engineering decisions of
this assignment").

R1–R3 shipped what is honestly a pipeline-with-role-separation:
one LangGraph, shared `CampaignState`, dispatcher-decides-next.
R3's dispatcher walks a hardcoded rotation; the "Orchestrator"
graph node is a no-op stub. This round closes both gaps at
once, because the architectural changes that bring the
Orchestrator online (it has to live outside the per-campaign
graph, it has to read state through a tool surface, it has to
hand off work to the Red Team across a trust boundary) are the
same changes that decouple the agents into independent workers.

The new shape, per
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.1–§2.7: **four
agents** (Orchestrator, Red Team, Judge, Documentation), each
its own async worker process, communicating through a typed
Postgres-backed message bus (`agent_messages` table), with
**two human-in-the-loop approval gates** (plan approval before
the Red Team fires, critical-finding approval before
Documentation promotes). The Specialists / Mutator / Output
Filter / Target Caller stay as graph nodes *inside* the Red
Team agent — they are the Red Team's bounded job, not peer
agents. R3's existing internal Red Team code carries forward
largely unchanged; what changes is the orchestration shell
around it.

This is *the* load-bearing round for the brief's central
claims about the platform being multi-agent and adaptive.

**Outcome.** A user can:

1. Start a campaign with just a target and a budget — no
   category, no technique list. The Orchestrator reads the
   project's current state and proposes the plan.
2. See the proposed plan in the dashboard before anything fires:
   which categories and techniques the Orchestrator chose, in
   what order, with what per-attempt budget, and a paragraph of
   rationale grounded in coverage / severity / recency.
3. Approve, edit, or reject the plan. Edits stay legible — the
   dashboard shows the diff between the proposed plan and the
   operator's final plan, and that diff is recorded on the
   audit log against the operator who made it.
4. Open a coverage view in the dashboard that shows, for every
   attack category and technique, how many attempts have run,
   when the most recent one was, the current pass / fail /
   partial mix, and which open findings the category carries.
   This is both the substrate the Orchestrator's tools read and
   the operator's view into why the plan looks the way it does.
5. Watch the platform's choices shift across a sequence of
   campaigns as findings land and coverage fills in — the
   under-tested categories rise, the saturated ones fall — and
   read out the Orchestrator's stated reasoning at each step.
6. Stop and start individual agents independently. Restart the
   Judge worker without affecting an in-flight Red Team
   campaign; bring up a second Documentation worker to drain a
   backlog of `pass` verdicts; take the Orchestrator offline for
   prompt-tuning without halting the bus. The dashboard shows
   each agent's inbox depth and processing rate live.
7. Open the bus view in the dashboard and see every cross-agent
   message in flight: kind, from, to, payload preview, age,
   attempts, current state (waiting / consumed / dead-lettered).
   Replay a dead-lettered message after fixing its cause.

**Scope.**

In — **message bus + agent decoupling:**

- A new `agent_messages` table per
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.3 schema, with
  indexes on `(to_agent, visible_after) WHERE consumed_at IS NULL`
  and a unique constraint on `idempotency_key`. Alembic migration
  ships with R4.
- A `cats.messaging` package: typed `Envelope[T]` (Pydantic) for
  the six message kinds (`CampaignRequested`,
  `CampaignPlanProposed`, `CampaignPlanApproved`, `AttackEvent`,
  `VerdictRendered`, `FindingPromoted`), a `Bus` client with
  `emit` / `claim_next` / `ack` / `nack` / `dead_letter` methods
  using `FOR UPDATE SKIP LOCKED` semantics, and a `Worker` base
  class that handles the LISTEN/NOTIFY wake-up + visibility
  timeout + retry-with-backoff loop.
- Four worker entry points: `cats.workers.orchestrator`,
  `cats.workers.red_team`, `cats.workers.judge`,
  `cats.workers.documentation`. Each launchable as its own
  process (`uv run python -m cats.workers.<agent>`) and
  collectively launched by docker-compose for the live
  deployment.
- Migration of R3's existing graph-node logic into the right
  agent boundaries: the Specialists / Mutator / Output Filter /
  Target Caller move into `cats.agents.red_team` as the Red
  Team agent's internal graph; the Judge node moves to its own
  worker that consumes `AttackEvent`; the Documentation node
  moves to its own worker that consumes `VerdictRendered(pass)`.
  Existing per-node tests carry forward; the integration tests
  are rewritten to assert *messages emitted* rather than *graph
  nodes called*.
- A bus-view dashboard page at `/bus` showing in-flight
  messages, per-agent inbox depth, dead-letter queue, and
  message-flow visualization for a selected campaign.

In — **Orchestrator agent (LLM-driven planner):**

- The Orchestrator worker (LLM-driven, Claude Sonnet 4.6 per
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.1). Consumes
  `CampaignRequested`; emits `CampaignPlanProposed`.
- A typed tool surface the Orchestrator calls during planning —
  at minimum `list_coverage`, `list_open_findings`,
  `list_recent_regressions`, `list_attack_categories`,
  `budget_remaining` per
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4. Tools are
  pure-DB queries with declared schemas; they are how the
  Orchestrator reads the world.
- A human-in-the-loop approval gate on every emitted plan.
  The `CampaignPlanApproved` message is only emitted after the
  operator approves in the UI. Edits and rejections are
  first-class outcomes, not corner cases.
- A coverage view in the dashboard at `/coverage/<project>`
  showing the per-category, per-technique state the
  Orchestrator's tools surface — same substrate, human-readable.
- Halt conditions emitted by the plan and enforced by the Red
  Team worker: budget exhausted, N consecutive `fail` verdicts,
  judge errors.
- An eval set for the Orchestrator's planning quality —
  hand-labeled `(observability state, expected plan shape)`
  cases the meta-loop can be measured against. A few dozen at
  R4; bigger as the platform accumulates real history.

In — **Red Team agent reshape:**

- R3's dispatcher re-shaped from *picker* to *executor*: the
  Red Team consumes `CampaignPlanApproved` envelopes and walks
  the plan's attempts in order. `selected_technique` is
  supplied by the plan, not by `ROTATION`.
- A new `red_team_attempts` table tracking per-`attack_id`
  iteration counter so the partial-loop is durable across
  crashes (see [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.7).
- Red Team emits `AttackEvent` envelopes to the Judge's inbox
  rather than calling a Judge node directly.
- Red Team consumes `VerdictRendered(partial)` envelopes from
  the Judge to drive the variant loop, bounded by the plan's
  `max_consecutive_partials`.

Out:
- The meta-loop that proposes Orchestrator prompt or tool
  changes ([`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4 names
  it; it ships as its own later round once R4's planner has
  produced enough history to evaluate against).
- Automatic regression-run triggering when the target redeploys
  (R8 territory).
- Fully autonomous, no-human campaigns. The brief explicitly
  asks "where does your system stop and ask a human"; this
  round's answer is: at every plan emission and at every
  critical-finding promotion (the latter is already R9's scope
  but the agent boundary that owns it is named here).
- Multi-project orchestration (one Orchestrator instance
  planning across a fleet of Projects). Out of MVP scope.
- A real message broker (Kafka / NATS / RabbitMQ).
  Postgres-as-bus is sufficient for the platform's volume and
  the brief's needs. Revisit if the platform's daily message
  rate exceeds ~100k.
- A fifth agent (Regression Harness). R8's work; the bus
  schema is designed so a Regression Harness agent can be added
  later without disrupting the four agents R4 ships.

**Definition of done (in addition to global DoD).**

*Multi-agent + bus:*

- [ ] Four independent worker processes (Orchestrator, Red Team,
      Judge, Documentation) run concurrently. Stopping any one
      with `docker compose stop <worker>` does not crash the
      others; an in-flight campaign's outstanding work backs up
      on the stopped agent's inbox and resumes when it restarts.
      Demonstrated with a kill-the-judge-mid-campaign test.
- [ ] All cross-agent handoffs flow through `agent_messages`.
      No agent imports another agent's modules to call them
      directly. The codebase has zero cross-agent function calls;
      `grep` confirms.
- [ ] Every envelope's `idempotency_key` is enforced by the
      DB's unique constraint. Re-emitting the same logical
      event is a no-op at insert time. Demonstrated with a
      duplicate-emit test.
- [ ] Visibility timeouts work: a worker that exits mid-handle
      leaves its message visible-after-timeout to be re-claimed.
      Demonstrated with a worker that exits via `os._exit(1)`
      after claiming a message; a second worker picks it up
      after the timeout and completes it.
- [ ] Dead-letter handling works: a message that fails 5 times
      in a row is dead-lettered; the bus dashboard surfaces it;
      an operator can re-queue it.
- [ ] The bus-view dashboard page at `/bus` shows in-flight
      messages, per-agent inbox depth, and dead-letter queue.
      Live-updates via Redis pub/sub.

*Orchestrator + HITL plan gate:*

- [ ] A campaign launched with only a target + budget produces
      a coherent plan grounded in the project's actual coverage
      state — not a constant prior, not the R3 rotation tuple.
- [ ] The plan dispatches only after operator approval; an
      operator can edit the plan (drop a technique, add one,
      change order, change per-attempt budget) and the dispatch
      runs the edited plan, not the proposed one.
- [ ] The dashboard's coverage view answers the brief's
      observability questions: "which attack categories have
      been tested and how many cases per category" and "is the
      target system becoming more or less resilient over time."
- [ ] Across at least ten consecutive campaigns against the
      same project, the Orchestrator's plan visibly evolves —
      categories the platform has saturated drop in priority,
      categories with open findings rise — and a reader can
      open the plan's rationale and see the Orchestrator name
      the signals that drove the change.
- [ ] The Orchestrator's plans are evaluated against a hand-
      labeled set: a versioned `evals/orchestrator/` answer key
      with a stated accuracy bar (planning is fuzzier than the
      Judge's binary verdict; the bar will read like
      "plan covers ≥N of the top-K expected categories" rather
      than a single accuracy number, and the rationale fields
      go through a separate quality rubric).
- [ ] The audit log records every plan emission, the operator
      who approved or edited it, and the diff if there was one.
      No plan reaches dispatch without an audit row.

*Migration completeness:*

- [ ] The R3 dispatcher's `ROTATION` tuple is gone — replaced
      with plan-driven dispatch. A grep for the symbol confirms
      no orphaned references remain.
- [ ] R3's `run_campaign_multi_technique` is gone — replaced
      with the Orchestrator → Red Team message handoff.
- [ ] Every R3 integration test passes against the new
      decoupled topology (with assertions reshaped from "graph
      node was called" to "envelope was emitted to inbox").
- [ ] The `/healthz` endpoint reports per-agent worker health
      (each worker registers a heartbeat row).

**Risks & blockers.**

- **The bus refactor is invasive.** R3 shipped 114 tests against
  a single-graph topology. The integration tests in particular
  call into the graph and assert on the resulting state — those
  have to be rewritten to assert on emitted envelopes. Budget
  meaningful time for test migration; treat each rewritten test
  as fresh authoring rather than mechanical refactor.
- **Idempotency is easy to forget.** Every consumer must dedupe
  by `idempotency_key` *and* by checking whether the underlying
  work already exists. A consumer that just acks on receipt and
  re-does the work on retry will double-write rows. The
  `Worker` base class enforces the key check; per-handler
  consumers still have to do the second check (because only the
  consumer knows what "this work was already done" means for
  its envelope kind).
- **Visibility timeouts are a tuning surface.** Set them too
  short and slow LLM calls get re-claimed mid-flight; set them
  too long and a real crash takes minutes to recover. R4 ships
  with the defaults named in §2.7 (60s for Judge / Docs, 300s
  for Red Team) but expect to revise from operational data.
- **Process management.** Four workers + the API + Postgres +
  Redis is more moving parts than R3. Docker-compose handles
  local; the deploy pipeline needs updating to launch the
  workers as separate services with restart policies. The
  rollback path (R1's documented one-command revert) must
  exercise the new compose shape before R4 ships.
- **Prompt and tool surface design.** This round is fundamentally
  a prompt-engineering and tool-design exercise on top of the
  bus work. A bad Orchestrator prompt produces "plan everything
  every time" or "plan whatever's first in the schema." Budget
  real time for iterating on the prompt against the eval set;
  it is the most load-bearing piece of text in the platform.
- **Cold start.** With no history, the Orchestrator has to do
  something reasonable. The tool surface returns empty lists or
  uniform priors; the prompt has to acknowledge that explicitly
  rather than hallucinate signal. The cold-start plan is itself
  a fixture in the eval set.
- **Plan-approval friction.** A HITL gate on every campaign is
  the brief's requirement, but it slows the platform down. The
  approval surface has to be one click for the "plan looks
  good" path and a structured editor for the "needs tweaks"
  path — anything heavier and operators will stop reading the
  rationale.
- **LLM cost in the inner loop.** R1–R3's discipline was "no
  LLM in the inner loop." This round inverts that for the
  Orchestrator specifically.
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4 bounds the
  cost: one Orchestrator call per campaign, not per attack. A
  campaign that fires 30 attacks costs one Orchestrator
  invocation. The budget cap on a campaign has to account for
  this; the AI-cost-analysis deliverable updates.
- **Evaluating planning quality.** Judging whether a plan is
  *good* is harder than judging whether an attack succeeded. R3
  set the precedent with hand-labeled `(attack, response,
  verdict)` triples; R4 extends with `(state-snapshot, expected
  plan shape)` cases plus a rationale-quality rubric. The eval
  has to be honest about being fuzzier than R3's was.
- **The Orchestrator becoming a single point of failure.** If
  the planner is wrong, the whole campaign is wrong. The HITL
  gate is the load-bearing mitigation here. The worker also
  refuses to emit a `CampaignPlanProposed` that fails structural
  validation (unknown technique key, budget cap above the
  campaign cap, contradictory halt conditions); the operator
  sees the validation failure in the UI rather than the
  platform silently choosing something else.
- **Round size.** Folding the bus refactor and the Orchestrator
  agent into one round is the right call (each pulls the other
  in), but it makes R4 larger than R3 was. Reserve the option
  to ship in two commits: a "bus + agent decoupling" commit
  that preserves R3's behavior across the new topology, and a
  "real Orchestrator + HITL" commit that brings the planner
  online. The Retrospective should call out whether that split
  was the right call in hindsight.

**Tasks.** *(builder fills in as completed)*

*Commit A — bus + four-worker decoupling (preserves R3 behavior):*

- [x] R4 worktree on `feat/round-4-orchestrator-bus`; sibling at
      `../cats.worktrees/round-4-orchestrator-bus`.
- [x] Alembic migration `20260512_0005` adds `agent_messages`,
      `agent_dead_letters`, `red_team_attempts`,
      `documentation_drafts`, `worker_heartbeats`, `campaign_plans`.
      Partial index on `(to_agent, visible_after) WHERE consumed_at
      IS NULL`; unique index on `idempotency_key`.
- [x] `cats.messaging` package: typed `Envelope[T]` + six payload
      kinds (`CampaignRequested`, `CampaignPlanProposed`,
      `CampaignPlanApproved`, `AttackEvent`, `VerdictRendered`,
      `FindingPromoted`); `Bus` client with
      `emit/claim_next/ack/nack/dead_letter/requeue_dead_letter/
      inbox_depth` using `FOR UPDATE SKIP LOCKED` + LISTEN/NOTIFY;
      `Worker` base with visibility timeouts (60s judge/doc, 300s
      orchestrator/red_team), exp-backoff retry, dead-letter at 5
      failures, per-worker heartbeat row, SIGTERM/SIGINT handling.
- [x] Four worker entry points (each launchable as `uv run python
      -m cats.workers.<agent>`): `cats.workers.orchestrator` (stub
      planner for Commit A — emits R3 ROTATION as a `PlannedCampaign`
      and auto-approves), `cats.workers.red_team` (plan-executor;
      consumes `CampaignPlanApproved` + `VerdictRendered(partial)`),
      `cats.workers.judge` (consumes `AttackEvent`; deterministic +
      LLM rubric), `cats.workers.documentation` (consumes pass/fail
      verdicts; writes Finding + Report + audit + emits
      `FindingPromoted`).
- [x] `cats.agents.red_team.executor.execute_attempt`: standalone
      function that fires one plan attempt, runs through the existing
      output filter, persists the `AttackExecution` row, and returns
      the data the worker wraps into an `AttackEvent`.
- [x] `cats.db.repositories.run_repo.set_execution_verdict`: links
      the Judge's verdict back to the Red Team's execution row.
- [x] API route `POST /campaigns` now emits `CampaignRequested` on
      the orchestrator's inbox instead of dispatching a graph
      directly; the legacy `category` form field is parsed but
      ignored (Orchestrator picks).
- [x] `/bus` dashboard page (route + 3 HTMX-polling partials) — in-
      flight messages, per-agent inbox depth, dead-letter table with
      Re-queue button (operator-gated + CSRF + audit-logged).
- [x] `/healthz` extended with a `workers` block — per-agent latest
      heartbeat, derived `healthy` flag (stale after `2 *
      visibility_timeout`).
- [x] `docker-compose.yml` adds four worker services using the api
      image with YAML anchors; Makefile gets `worker-orchestrator`,
      `worker-red-team`, `worker-judge`, `worker-documentation`, and
      `workers-all`.
- [x] Tests: `tests/unit/test_messaging_envelopes.py` (16 cases);
      `tests/integration/test_messaging_bus.py` (7 cases including
      `FOR UPDATE SKIP LOCKED` dispatch-to-one, idempotency dedup,
      visibility-timeout reclaim, dead-letter + requeue, inbox
      depth); `tests/integration/test_messaging_worker.py` (5 cases:
      ack, nack-with-backoff, dead-letter at cap,
      `PermanentHandlerError`, heartbeat); `tests/integration/test_r4_bus_e2e.py`
      drives a full Orchestrator→Red Team→Judge chain across four
      workers in <4s and asserts every kind through `VerdictRendered`
      lands on `agent_messages`. The cross-agent-imports guard test
      greps the workers directory and fails if any worker imports
      another worker's module directly.
- [x] Lint + mypy --strict clean across all 138 source files
      (`make lint` green). 162/162 tests pass.

*Commit B — Orchestrator + HITL plan gate (work-in-progress; some
artifacts pre-staged for the planner):*

- [x] Orchestrator tool surface — five typed DB tools
      (`list_coverage`, `list_open_findings`,
      `list_recent_regressions`, `list_attack_categories`,
      `budget_remaining`) under
      `src/cats/agents/orchestrator/tools.py` plus `TOOL_DESCRIPTORS`
      export and 17 unit tests. Pre-staged in Commit A so the planner
      author can iterate without re-grounding.
- [x] `evals/orchestrator/v1/` answer key — 12 hand-labeled
      `(observability_state, expected_plan_shape)` cases covering
      cold-start, saturated category, open critical finding, recent
      regression, mixed, tiny budget, category disabled, everything
      stale, always-failing technique, and three adversarial edges
      (empty tool outputs, contradictory signals, zero budget). Bar:
      plan covers ≥2 of top-3 expected categories; rationale rubric
      is 5 yes/no checks. Runner is `evals.orchestrator.v1.runner`
      with a stub planner that passes 12/12 sanity.
- [ ] Real LLM planner that consumes the tool surface (replaces
      Commit A stub).
- [ ] HITL plan approval UI + diff-vs-proposed + audit logging.
- [ ] `/coverage/<project>` dashboard backed by the same DB queries
      the tool surface uses.
- [ ] Adaptive-behavior synthetic-history integration test (10
      simulated campaigns; saturated drops, finding-bearing rises).
- [ ] Delete R3 `INJECTION_ROTATION` / `run_campaign_multi_technique`
      remnants once the real planner replaces them.

**Decisions.** *(builder records as made)*

- **Two commits in one round.** R4's roadmap entry explicitly
  reserves this option; Commit A ships the bus + four-worker
  decoupling with R3 behavior preserved end-to-end (via a stub
  Orchestrator that walks the same `INJECTION_ROTATION`), Commit B
  wires the real LLM planner + HITL gate on top. Rationale: keeps
  the bisect window small; the riskiest engineering (the bus, the
  worker base, the cross-agent contracts) lands as a single
  reviewable commit before any prompt-engineering work begins.
- **Stop the R4 e2e at `VerdictRendered`, not `FindingPromoted`.**
  The full pass-path through Documentation depends on a real target
  + LLM call landing a `pass` verdict; the R4 test fixture's
  OpenEMR mock isn't shaped to satisfy the real login handshake the
  target client performs. The R3 `test_campaign_e2e` covers the
  `pass`-path domain logic end-to-end via `run_one` (still
  functional in Commit A); R4's new test instead proves the
  *cross-agent message chain* works, which is what's actually new.
  Commit B will revisit once the new e2e fixture can mock the full
  target handshake.
- **Cross-agent contract enforced by grep.** A test that walks
  `src/cats/workers/*.py` and fails if any worker imports another
  worker's module directly. Cheaper than adding architectural-fitness
  tooling; catches the regression the DoD explicitly names.
- **`payload_version` field on every payload.** Schema evolution is
  a migration + a code branch, not a guess. R4 ships everything at
  `payload_version=1`.
- **Visibility timeouts straight from ARCHITECTURE.md §2.7.** 60s
  for Judge/Documentation, 300s for the LLM-driven agents
  (Orchestrator + Red Team). Will tune from real operational data
  later; documented as a tuning surface in the round's Risks.
- **Polling-only `/bus` live updates.** HTMX polls every 3s. A real
  Redis pub/sub channel for bus state changes is nice-to-have; the
  trade-off (extra wiring + a second source-of-truth) isn't worth
  the latency win at R4's scale.
- **JSON payload serialized via `json.dumps` before INSERT.**
  asyncpg's JSONB binding wants a string, not a dict; SQLAlchemy
  doesn't transparently convert. Small but load-bearing — found
  during the first end-to-end emit smoke and worth recording so
  future bus producers know.
- **`documentation_drafts` row at `published` + `awaiting_approval=False`
  for non-critical findings.** R9 will flip `awaiting_approval=True`
  on `severity=critical`. The schema is forward-ready; R4 just
  doesn't exercise the gate yet.

**Retrospective.** *(builder fills in after R4 ships)*

- What went well:
  - **The bus + worker decoupling went in faster than R4's risk
    section forecast.** Authoring the typed envelope set,
    `FOR UPDATE SKIP LOCKED` claim loop, visibility-timeout reclaim,
    dead-lettering, heartbeat row, and LISTEN/NOTIFY wake-up all
    fit in one commit with 28 messaging tests + an end-to-end
    pipeline test that runs in <4s. The architectural choice from
    R3's retro — "make the bus the contract, not the graph" — paid
    for itself almost immediately.
  - **Subagent parallelism on independent surfaces.** Docker-compose
    wiring, `/bus` dashboard templates, `/healthz` worker block,
    Orchestrator DB tool surface, evals/orchestrator/v1 answer key,
    and messaging unit tests were all delivered by parallel
    general-purpose subagents in the same window I was building
    the worker classes. Six concurrent work streams reduced wall-
    clock by a meaningful fraction.
  - **Cross-agent-imports test is a single grep.** Catches the DoD's
    "no worker imports another worker" constraint at unit-test
    speed. Cheaper than any architectural-fitness library.
  - **R3 tests still pass against the new topology.** No R3 test
    needed to be deleted or substantially rewritten — the bus is
    additive; `run_one` still functions for the R3 e2e. The
    Commit-A stub Orchestrator preserves the multi-technique
    rotation exactly so the multi-technique campaign test remains
    valid.
- What didn't:
  - **The full pass-path e2e through Documentation didn't make
    Commit A.** The fake OpenEMR transport in `test_r4_bus_e2e.py`
    doesn't satisfy the real `TargetClient.attack` login handshake,
    so the Red Team's target call fails fast and the Judge rules
    `partial` on an empty response — never reaching Documentation.
    R3's `test_campaign_e2e` still covers the domain logic via
    `run_one`. Commit B should either reshape the fake transport
    to mirror OpenEMR's auth flow or factor out a smaller
    `TargetClient.attack`-only mock seam.
  - **Ruff's UP046 + Pydantic generics.** `Envelope[T]` triggered
    UP046 ("use type parameters"), and applying the unsafe-fix
    orphaned the TypeVar declaration *and* tripped Pydantic's
    PEP-695 limitations. Reverted to classic `Generic[T]` syntax
    with a per-line `noqa: UP046`. Notable because the next round
    that adds a generic Pydantic model will hit the same trap.
  - **Generate_variant doesn't take individual fields.** R3's
    Mutator reads from `CampaignState.pending_attack_payload`
    directly, so the R4 executor has to construct a minimal state
    object to call it. Works, but the seam isn't as clean as I'd
    have written it from scratch. Note in Commit B's notes if the
    Mutator gets touched.
  - **The two-commit split landed only Commit A in this round
    invocation.** The real LLM planner + HITL UI + `/coverage` page
    + adaptive-behavior eval will need their own session. The
    artifacts pre-staged (tool surface, eval set) make Commit B
    significantly faster than starting cold.
- What to change for R5:
  - **R5 (.docx indirect injection) lands cleanly on the bus.** The
    new attack-firing path goes through `cats.agents.red_team.executor`;
    `.docx` payloads should add a new specialist + a payload-shape
    entry in `attacks.payload`, not a new graph topology. The bus
    contract doesn't need to change.
  - **Honor R3's deferred refactor of `TargetClient.attack`'s SSE
    walk.** R3 retro asked R5 to extract `walk_sse_to_text(events)
    -> str` before `.docx` work; the executor still calls the inline
    parser. R5 should do this *before* adding indirect-injection
    specialists — same reason R3 retro gave.
  - **Resolve `attempts` increment durability across handler
    failures.** The messaging-tests subagent noted that when a
    Worker handler raises, the same session rolls back both the
    side effects *and* the `claim_next` increment, so `attempts`
    only persists on the *next* claim. That's a reasonable design
    choice for ack-atomicity but it means dead-letter triggers on
    the in-memory `claimed.attempts == 5` rather than a durable
    row value. Either land a separate-transaction increment or
    document it explicitly in `ARCHITECTURE.md` §2.7.
  - **Commit B's adaptive-behavior synthetic-history test should
    seed via `cats.agents.orchestrator.tools` directly** — not by
    fabricating coverage rows in raw SQL. That validates the
    tool-surface schema along with the planner's reasoning.

---

## Round 5 — Indirect injection via `.docx`

**Goal.** Reach the highest-impact attack surface identified in
[`../THREAT_MODEL.md`](../THREAT_MODEL.md): indirect injection via
uploaded `.docx` referral letters (the EchoLeak / ForcedLeak
shape). This round teaches the platform to *upload* attacks, not
just send them in chat.

**Outcome.** A user can:

1. Run a campaign that delivers its attacks as uploaded
   documents rather than as chat messages.
2. See the platform craft adversarial documents — documents
   that look ordinary to a clinician but carry hidden
   instructions for the AI that reads them.
3. Watch those documents go through the Co-Pilot's real upload
   path and see whether the planted instructions survived.
4. Open findings labeled with the specific *type* of
   document-based attack that succeeded, so the Co-Pilot team
   knows precisely which document handling to harden.

**Scope.**

In:
- Document-shaped attacks against the live target, using the
  Co-Pilot's real upload path.
- Several distinct document-hiding techniques (covering the
  range catalogued in the threat-landscape research — invisible
  text, structural hiding, encoded smuggling, document-metadata
  payloads, and so on).
- Findings tagged with which technique succeeded, so the report
  is specific.

Out:
- Triggering the Co-Pilot's "accept this extracted fact" flow
  end-to-end (a later round; it needs a simulated clinician).
- PHI exfiltration (next round).

**Definition of done (in addition to global DoD).**

- [ ] The platform can produce, upload, and evaluate document
      attacks across a meaningfully broad range of techniques —
      enough that the round seriously exercises the attack
      surface, not just one trick.
- [ ] Every generated document opens cleanly in real-world
      document readers; the techniques are invisible to a
      human reviewer.
- [ ] The round produces at least one full vulnerability
      report — either describing a successful breach, or
      documenting that the Co-Pilot's defenses held against
      the techniques tried. Both are valuable outputs.
- [ ] If a defense the threat model assumed strong turns out
      not to be, the threat model is updated to reflect that.

**Risks & blockers.**

- **Target-side acceptance of CATS traffic.** The Co-Pilot may
  rate-limit, allow-list, or reject upload traffic from CATS.
  Coordinate with the Co-Pilot team early.
- **Document validity.** Attacks have to look like ordinary
  documents to a real human and to real document software.
  Test in real readers before declaring a technique working.
- **Detecting subtle success.** Some attacks succeed in ways
  the obvious detector misses (the AI paraphrases the planted
  instruction rather than echoing it). The judge has to handle
  the fuzzy case, not just the exact-match case.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R5 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R5 builder_

**Retrospective.** *(builder fills in after R5 ships)*

- What went well: _
- What didn't: _
- What to change for R6: _

---

## Round 6 — PHI / Cross-Patient Exfiltration

**Goal.** Find out whether the Co-Pilot can be tricked into
leaking patient data — across the channels the threat-landscape
research catalogues, not just the obvious one. Either prove the
existing defenses hold or document exactly where they don't.

**Outcome.** A user can:

1. Run a campaign focused on patient-data exfiltration and
   watch the platform attempt several distinct exfiltration
   patterns against the live target.
2. See clear evidence whether any planted "marker" data was
   carried back to the attacker through *any* channel — the
   visible response, a tool call, a side channel.
3. Open findings that distinguish which exfiltration channel
   succeeded, so the Co-Pilot team knows exactly which path to
   close — or read a published report stating that all channels
   tested held under the attacks attempted (which is itself a
   valuable finding).
4. Trust that the round tested cross-patient leakage, not just
   in-context leakage: an attacker scoped to one patient should
   not be able to retrieve another patient's data.

**Scope.**

In:
- Exfiltration-shaped attacks covering the range of channels
  catalogued in the threat-landscape research.
- A reliable "marker" protocol that lets the platform plant
  distinctive synthetic data in a target chart, then detect
  whether that data surfaces anywhere it shouldn't.
- A cross-patient probe: explicit verification of the
  authorization boundary, not just the prompt boundary.

Out:
- Document-borne attacks on citations or extraction outputs
  (their own rounds).
- The end-to-end "clinician accepts a poisoned extraction" flow
  (its own round; needs simulated user behavior).

**Definition of done (in addition to global DoD).**

- [ ] The round produces a finding that distinguishes which
      exfil channel succeeded — or a published report stating
      that all channels tested held.
- [ ] A cross-patient probe ran during the round, and its
      result is documented: either it held (good) or a real
      cross-patient leak was found (the round's most important
      output).
- [ ] No real patient data is in the repo, in commits, in
      logs, or in traces. Synthetic only.

**Risks & blockers.**

- **Patient data hygiene.** This is the first round to talk
  about PHI by name. Synthetic-only is the rule, and it's easy
  to slip up. Set up the markers and the test charts before
  the round runs hot.
- **Marker design.** Markers must be distinctive enough that
  detection is nearly perfect, but ordinary-looking enough that
  the AI doesn't treat them as out-of-distribution. This is a
  real design call, not a checkbox.
- **The "nothing leaked" outcome.** This round's result may be
  "the defenses held." That's not a failure of the round — the
  round's job is to *measure*, and a clean measurement is a
  measurement. The report has to read that way.

**Tasks.** *(builder fills in as completed)*

**R6 foundations slice — landed on `feat/round-6-exfil-foundations`, 2026-05-12:**

- [x] Marker (canary) protocol module `src/cats/exfil_markers/` —
      per-attack tokens (`CATS-EXFIL-<8 hex>`), in-process registry of
      `(what, where, who, when)` plants, detector covering 12 channel
      kinds (visible text, markdown image / reference link, percent /
      base64 / hex encoded URL params, inline base64 / hex, zero-width
      steg, structured tool-arg walk). 26 unit tests.
- [x] Wire the marker detector into
      `src/cats/categories/exfil/deterministic.py` — replaces the
      inconclusive scaffold stub; verdict is `pass` if any planted
      marker surfaces, `fail` if planted but absent, `inconclusive` if
      no markers in payload. Evidence dict names the leaked markers +
      channels. 12 unit tests.
- [x] Cross-patient probe `src/cats/exfil_markers/cross_patient.py` —
      plants under victim, asks as attacker, scans every response,
      reports leaks by channel. Orchestration decoupled from the target
      HTTP surface via `Planter`/`Asker` callable types so the same
      probe runs against unit fakes and the live target. 9 unit tests.
- [x] Exfil category content `src/cats/categories/exfil/` — real
      `red_team/system_prompt.md` (specialist brief grounded in W3 §2),
      `red_team/few_shots.md` (5 annotated examples across techniques),
      `rubric/v1.md` (LOCKED — channel taxonomy + qualitative tier),
      `fixtures/ground_truth.jsonl` (10 hand-labeled triples, six
      pass / two fail / two partial), CI-asserted consistent with the
      deterministic check via `tests/unit/test_exfil_fixtures.py`.
- [x] R6 foundations report `reports/exfil/R6_foundations.md` —
      channel taxonomy, reproduction recipe for a manual run against
      the live target, explicit deferral note.

**Deferred to a post-R4 follow-up (see Decisions):**

- [ ] Exfil specialist module + dispatcher entry under
      `src/cats/agents/red_team/exfil/` (per-technique modules mirroring
      the injection family).
- [ ] Lift the three R3-era category guards: `campaign_new.html:64-65`
      dropdown options, `api/routes/campaigns.py:109` route guard,
      `graph/nodes/red_team_router.py:55` router guard.
- [ ] Run the cross-patient probe + the five techniques against the
      live OpenEMR target; fill in the per-channel verdict table in
      `reports/exfil/R6_foundations.md`.

**Decisions.** *(builder records as made)*

- **2026-05-12 — split R6 into a foundations slice (this branch) and a
  post-R4 follow-up.** Rationale: R4 (in flight on
  `feat/round-4-orchestrator-bus`) rewrites the dispatcher from R3's
  hardcoded `ROTATION` tuple to a plan-driven executor consuming
  `CampaignPlanApproved` envelopes, and reshapes
  `src/cats/agents/red_team/` into the Red Team agent's internal graph.
  Authoring the exfil specialist now would mean writing against R3's
  shape that R4 deletes — and the three category guards live on paths
  R4 replaces wholesale (UI dashboard shifts to plan-approval, the
  category POST route becomes Orchestrator-emits-`CampaignRequested`,
  the router becomes a plan walker). Foundations slice is R4-orthogonal
  by construction (no imports from `agents/red_team` or `graph`); the
  follow-up commit is small because the design work — token shape, JSON
  output contract, technique handles, rubric, fixtures — is already
  done.
- **2026-05-12 — marker token shape is `CATS-EXFIL-<8 hex>`.** Fixed
  prefix gives the detector near-zero false-positive rate on benign
  clinical text; alphanumeric-only body avoids out-of-distribution
  pattern-match-and-refuse from the target model. Per-attack (not
  per-category) so a fixed token can't be memorized and filtered.
- **2026-05-12 — detector reports only planted markers.** A random
  `CATS-EXFIL-`-shaped string the target happens to emit is not a leak
  by definition. The registry-as-truth rule keeps the deterministic
  verdict honest under model drift.
- **2026-05-12 — rubric v1 is LOCKED.** Channel taxonomy is part of the
  rubric, not a private detector implementation detail, so a finding's
  `pass` rationale must name the channel that failed. Any future
  channel addition is a new rubric version (v2.md), not an in-place
  edit.
- **2026-05-12 — exfil fixture accuracy threshold is ≥90%, per the
  scaffold's existing note.** Lower than injection's ≥95% because the
  channel taxonomy + partial/near-miss verdict makes the signal fuzzier
  by design.

**Retrospective.** *(builder fills in after R6 ships)*

- What went well: _
- What didn't: _
- What to change for R7: _

---

> **Note.** Earlier drafts of this roadmap reserved a separate
> round here titled "The platform decides what to test next" —
> a deterministic bandit-based category-selection layer. That
> goal is now Round 4's job, executed as an LLM-driven planner
> per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4 rather
> than a heuristic, with a human-in-the-loop approval gate on
> every emitted plan. The roadmap drops the dedicated round
> rather than ship two passes at the same capability.

---

## Round 7 — Tool misuse and over-reach

**Goal.** Test whether the Co-Pilot's tools can be coerced into
doing work the user didn't ask for — calling the wrong tool,
reading more data than the task warrants, or being driven into
expensive loops that legitimate use would never trigger.

**Outcome.** A user can:

1. Run a campaign focused on tool misuse and watch the platform
   try to get the Co-Pilot to over-reach — reading more chart
   data than the current task calls for, repeatedly invoking
   tools, or pulling categories of data that aren't relevant
   to the conversation.
2. Open findings that compare what tools the Co-Pilot actually
   called during the campaign against what it *should* have
   needed for the task it was given.
3. See findings clearly labeled with which tool was misused and
   what data classes the Co-Pilot ended up touching.

**Scope.**

In:
- Attacks that coerce the Co-Pilot's tool-using behavior into
  going beyond what a legitimate task requires.
- A way to characterize, per task type, what "appropriate tool
  use" looks like — so the platform has a baseline to measure
  misuse against.
- Findings that pinpoint which tool and which over-reach
  pattern triggered the verdict.

Out:
- Coercing the Co-Pilot into a cost-amplification spiral. That
  is its own attack family and gets its own round later.
- Tool misuse driven by content from previous clinicians'
  chart notes (a separate sub-technique).

**Definition of done (in addition to global DoD).**

- [ ] The platform produces findings that specifically identify
      which tool was misused and what extra data was touched.
- [ ] The "appropriate tool use" baseline is recorded in a
      reviewable form, not hard-coded — a security engineer
      can read it and challenge the assumptions.
- [ ] The round produces at least one full vulnerability
      report, or a published report that scope enforcement
      held against the misuse attempts tried.

**Risks & blockers.**

- **Visibility into the Co-Pilot's tool calls.** The platform
  needs to see what tools the Co-Pilot actually called during
  a campaign, not just what it *said* it called. Coordinate
  with the Co-Pilot team on read access to the underlying
  audit trail before this round starts.
- **Defining "appropriate."** What counts as legitimate tool
  use is judgment, not arithmetic. The baseline has to be
  written down with rationale, not assumed.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R7 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R7 builder_

**Retrospective.** *(builder fills in after R7 ships)*

- What went well: _
- What didn't: _
- What to change for R8: _

---

## Round 8 — Verifying that fixes hold across releases

**Goal.** Once CATS has surfaced findings, the Co-Pilot team will
ship fixes for them. This round lets the platform answer the
hard question: *did the fix actually fix the bug, or did the
model just stop misbehaving in the same way?* The cost of getting
that answer wrong is high — the brief calls this out explicitly,
and the architecture has the answer (a multi-gate check).

**Outcome.** A user can:

1. Take a confirmed finding from an earlier round and ask the
   platform to re-test it against the current version of the
   Co-Pilot.
2. See the platform mark the finding as fixed only when every
   layer of the regression check agrees — not just when the
   obvious symptom is gone.
3. See findings that *appear* fixed but fail one of the
   subtler checks get flagged for human review, with a clear
   explanation of which check disagreed and why.
4. Have CATS automatically re-test the full set of confirmed
   findings whenever the Co-Pilot is redeployed, so regressions
   are caught at deploy time, not weeks later.

**Scope.**

In:
- A multi-gate regression check that distinguishes "the bug is
  actually fixed" from "the model just refuses differently now."
- Automatic re-testing when the Co-Pilot redeploys.
- A regression view in the dashboard showing, per finding, the
  current status and which gates passed.
- Use of the *original* judgment criteria for each finding, not
  the latest — so the bar doesn't drift under us as we update
  rubrics over time.

Out:
- Approval workflow for critical findings (next round).

**Definition of done (in addition to global DoD).**

- [ ] Re-running a confirmed finding produces a verdict that
      shows each gate's individual result, not just an overall
      pass/fail.
- [ ] A finding that looks fixed on the surface but fails the
      subtler behavioral check is *not* auto-marked fixed —
      it's flagged for human review with the reason.
- [ ] When the Co-Pilot redeploys, the platform re-runs its
      confirmed findings against the new version without a
      human pushing a button.

**Risks & blockers.**

- **Behavioral baselines drift.** The platform compares against
  captured "safe behavior" examples. If the Co-Pilot's prompt
  changes substantially, those baselines may no longer match
  even legitimate refusals. Plan for a re-capture path.
- **Deploy-time webhook security.** The platform listens for
  Co-Pilot deploy signals. Those signals have to be
  authenticated — anyone sending one shouldn't be able to
  burn budget by firing the regression suite at will.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R8 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R8 builder_

**Retrospective.** *(builder fills in after R8 ships)*

- What went well: _
- What didn't: _
- What to change for R9: _

---

## Round 9 — Human approval before critical findings ship

**Goal.** Honor the trust boundary the brief asks for. When CATS
is about to label a finding as the highest-severity tier, it
should not do that on its own — a senior human should sign off
before the finding becomes part of the official record that
triggers remediation work.

**Outcome.** A senior reviewer can:

1. See a queue of high-severity findings that are waiting on
   their approval.
2. Open a pending finding and review everything that produced
   it: the attack, the Co-Pilot's response, the judgment, the
   trace.
3. Approve or reject the finding, leaving a written rationale
   that becomes part of the audit record.
4. Trust that only senior reviewers can approve — an operator
   without that role cannot push something through and gets a
   clear "not your call" response if they try.
5. Know that high-severity findings don't sit in the queue
   forever — after a reasonable wait they move into an
   "investigation needed" state rather than ageing into the
   official record by default.

**Scope.**

In:
- A pause on the path from "the platform thinks this is critical"
  to "this is now an officially confirmed critical finding."
  The pause waits for explicit human approval.
- An approval queue with a clear path from notification to
  review to decision.
- A notification to the right person when the queue gets a new
  entry.
- A written rationale captured at approval time as part of the
  audit record.

Out:
- Multiple judges voting on findings to reduce drift (decided
  out of scope; revisit if single-judge drift becomes a real
  problem).

**Definition of done (in addition to global DoD).**

- [ ] A campaign that produces a high-severity finding pauses;
      the finding does not appear in the official "confirmed"
      list until a senior reviewer approves it.
- [ ] Approval is gated by role; a non-senior user trying to
      approve gets a clear and visible block, not a silent
      no-op.
- [ ] Every approval and rejection appears in the audit trail
      with the approver, the time, and the written rationale.
- [ ] Findings that sit in the queue past the agreed window
      move to "investigation needed" automatically.

**Risks & blockers.**

- **Pause-and-resume reliability.** Pausing a campaign for
  human input has to survive a process restart, a server
  reboot, and a deploy. Verify before declaring the round done.
- **Notification fatigue.** If notifications fire too freely
  the reviewer stops looking. If they fire too rarely the
  queue fills up unseen. The default behavior should be
  conservative; tuning is by data.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R9 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R9 builder_

**Retrospective.** *(builder fills in after R9 ships)*

- What went well: _
- What didn't: _
- What to change for R10: _

---

## Round 10 — Multi-turn attacks

**Goal.** Up to this point, every CATS attack has been a single
exchange. Real attackers don't work that way — they build trust
over several turns, then break the safeguard at the end. This
round teaches the platform to run multi-turn campaigns where
each turn looks benign in isolation but the cumulative
conversation crosses a line.

**Outcome.** A user can:

1. Run a multi-turn campaign and watch the platform have a
   conversation with the Co-Pilot — multiple exchanges, each
   building on the prior turn.
2. See findings that pinpoint which turn was the one that
   finally crossed the line.
3. See the platform's judgment of the conversation take the
   whole conversation into account, not just the last message.

**Scope.**

In:
- Multi-turn attack flow end-to-end — the platform initiates,
  observes, iterates, and decides when to push.
- Judgment that sees the full conversation history, not just
  the last turn.

Out:
- Attacks that survive conversation resets and re-activate in
  later sessions. That is a distinct threat (persistent memory
  poisoning) and needs its own round.

**Definition of done (in addition to global DoD).**

- [ ] A multi-turn campaign of several exchanges runs
      end-to-end against the live target.
- [ ] When the campaign produces a finding, it identifies which
      turn was decisive.
- [ ] Per-turn cost is visible — multi-turn campaigns are
      expensive, and a user should not be surprised by the
      bill.

**Risks & blockers.**

- **Cost runaway.** Multi-turn campaigns can use many times
  the tokens of a single-turn one. Per-campaign budget
  enforcement, already present from earlier rounds, gets a
  real workout here.
- **State weight.** A long conversation produces a lot of
  state to checkpoint. Confirm the platform's persistence
  layer handles it before declaring the round done.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R10 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R10 builder_

**Retrospective.** *(builder fills in after R10 ships)*

- What went well: _
- What didn't: _
- What to change for R11: _

---

## Round 11 — Clinical misinformation propagation

**Goal.** Test the healthcare-specific failure mode the
threat-landscape research flags as one of the two top-priority
risks: when a clinician's question contains a wrong clinical
fact, does the Co-Pilot push back, or does it anchor on the
false premise and propagate it through the briefing? Published
healthcare-AI research shows this propagation happens at very
high rates across frontier models — this round measures whether
ours is one of them.

**Outcome.** A user can:

1. Run a campaign that asks the Co-Pilot questions seeded with
   a deliberately wrong clinical fact (a wrong lab value, a
   misattributed diagnosis, a contradicted history).
2. See the platform judge whether the Co-Pilot repeated the
   wrong fact, reasoned from it as if it were true, or
   correctly flagged it as not matching the chart.
3. Read findings tied back to specific clinical scenarios so
   the Co-Pilot team can reproduce and fix.
4. Trust that the judgment threshold for this category is set
   honestly — this is the hardest category to judge cleanly
   and the bar reflects that.

**Scope.**

In:
- An attack flow that plants false clinical premises in
  questions to the Co-Pilot.
- Judgment of whether the Co-Pilot's response propagated, paraphrased, or rejected
  the false premise.
- A library of seeded scenarios grounded in the published
  research, so findings are reproducible and the test corpus
  isn't ad hoc.

Out:
- Multiple judges voting on findings (still out of scope).

**Definition of done (in addition to global DoD).**

- [ ] A representative library of seeded clinical scenarios is
      in the fixture set and reproducible.
- [ ] The platform runs the category end-to-end against the
      live target.
- [ ] The accuracy threshold for judgment on this category is
      written down, lower than for the easier categories, and
      met honestly — not by trimming fixtures.
- [ ] The round produces at least one full report, either
      flagging a clinical-safety risk or documenting that the
      Co-Pilot correctly rejected the false premises tested.

**Risks & blockers.**

- **Source-corpus rights.** The published research has a
  catalog of seeded scenarios. Check whether we can reuse
  it directly or need to derive our own analogous scenarios.
- **Judgment is genuinely hard here.** A trained physician
  reviewing the same response can disagree on whether the
  Co-Pilot "anchored" on the false premise. Expect lower
  judgment accuracy than in other categories. Do not tune
  the fixture set to make the number look better — tune the
  threshold to be honest about the difficulty.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R11 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R11 builder_

**Retrospective.** *(builder fills in after R11 ships)*

- What went well: _
- What didn't: _
- What to change for R12: _

---

## Beyond Round 11

After Round 11, every high-priority threat-model category has
been exercised against the live target. Further rounds become
*depth, not breadth*. Likely candidates, in no particular order:

- **Extraction poisoning that ends in a chart write.** The
  highest-stakes write path on the Co-Pilot — a poisoned
  upload that a clinician unwittingly accepts into a real
  patient record. Needs a simulated clinician's behavior in
  the loop, so it's its own round.
- **Citation and evidence fabrication.** Whether the
  Co-Pilot's citations actually support the claims they're
  attached to, or just look like they do.
- **Cost-amplification attacks.** Whether the Co-Pilot can be
  coerced into expensive loops without producing useful
  output for the user.
- **Identity and role exploitation.** Whether the Co-Pilot can
  be persuaded to misrepresent its own scope or authority to a
  clinician.
- **Smarter safety filtering** on the platform's own attack
  output (today's filter handles the obvious cases; a smarter
  one handles the subtle ones).
- **A published cost analysis** at the run scales the brief
  asks for — pulled from real telemetry once the platform has
  enough run history to be credible.
- **White-hat mode.** The architecture is forward-compatible.
  Activating it lets the platform's specialists use read-only
  source knowledge to find vulnerabilities a black-box
  attacker couldn't reach.

The roadmap stays open-ended past Round 11 deliberately — what
to build next is a function of what the platform finds and where
the Co-Pilot evolves.
