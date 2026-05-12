# CATS test suite

Two layers:

- `tests/unit/` — fast, deterministic, no Postgres / Redis. Imports
  `cats.*` directly. Uses `FakeLLMClient` from `cats.llm.client` for
  anything that would otherwise hit an LLM.
- `tests/integration/` — runs against the **real** local Postgres +
  Redis from `docker compose up -d postgres redis`. Uses httpx
  `ASGITransport` to mount the full FastAPI app in-process; uses
  `MockTransport` to fake out the outbound HTTP calls (OpenEMR proxy,
  OpenRouter).

Run everything: `make test` · just units: `make test-unit`.

---

## Patterns the suite relies on (read this first if a test is acting weird)

### 1. Per-test engine + lifespan

`tests/integration/conftest.py::client` resets the module-level
`cats.db.engine._engine` cache before each test and disposes it after.
This is because `pytest-asyncio` runs each test in its own event loop;
a cached engine from a previous test points at a closed loop and you
get `RuntimeError: Event loop is closed` or `attached to a different
loop` errors that look like SQLAlchemy bugs but are loop-scoping bugs.

The lifespan context (`app.router.lifespan_context(app)`) runs inside
the test's loop too, so the admin user seeding and any later
on-startup logic exercises the same loop as the test body.

### 2. CSRF helper

R2 closes the R1 CSRF gap. Every state-changing POST requires both a
matching `cats_csrf` cookie and either an `X-CSRF-Token` header or a
form field `csrf_token`. `tests/integration/conftest.py::csrf_post`
wraps this: it warms the cookie via a `/healthz` GET if absent, then
POSTs with the matching `csrf_token` form field. **Tests using plain
`client.post(...)` against any mutating route will fail with 403** —
that's the system working as intended.

### 3. `cats.config.settings` monkeypatch

`Settings` is loaded once at import time via `@lru_cache`, then the
module attribute `settings` is bound to that instance. Reaching into
`monkeypatch.setenv("CATS_X", "y")` after the first import does
nothing visible — the cached `settings` already has the old value.

Two correct workarounds:

```python
# 1. monkeypatch the module attribute directly (preferred for the
#    health-check tests):
from cats.health import checks as mod
monkeypatch.setattr(mod.settings, "openrouter_api_key", "sk-test")

# 2. set the env BEFORE cats.config imports — only works at the very
#    top of conftest.py, before the first `from cats... import`.
import os
os.environ["CATS_X"] = "y"
from cats.config import _load
_load.cache_clear()  # so the next access rebuilds
```

R3 should move `settings` behind a `Depends(get_settings)` /
testable-factory pattern so this dance goes away — flagged in R1 retro
and still open.

### 4. FakeLLM via `install_override`

Tests don't need to know whether OpenRouter is reachable. The pattern:

```python
from cats.llm.client import FakeLLMClient, install_override

fake = FakeLLMClient()
fake.register("redteam_injection", lambda messages: '{"title":"...", ...}')
install_override(fake)
try:
    ...  # exercise the graph
finally:
    install_override(None)
```

`get_llm()` (called from inside graph nodes) checks the override first
and returns the fake when one is installed. The override is process-
global so tests must clean up — the autouse fixture in
`test_campaign_e2e.py::_install_fake_llm` does this for you.

### 5. Mocking the outbound HTTP to OpenEMR

`tests/integration/test_campaign_e2e.py::patch_target_transport` shows
the pattern: monkey-patch `httpx.AsyncClient` inside `cats.target.client`
to use an `httpx.MockTransport` that returns canned responses. The
mock sniffs the outbound request body for the canary token and echoes
it back so the deterministic judge sees a `pass`.

### 6. Live-target marker

Real-target tests (no FakeLLM, real OpenEMR, real OpenRouter) use the
`live_target` pytest marker:

```python
@pytest.mark.live_target
def test_real_openemr_login():
    ...
```

These don't run by default. To run them: `pytest -m live_target` with
`OPENROUTER_API_KEY`, `CATS_LIVE_OPENEMR_URL`, etc. set in your env.
(Not used in CI; reserve for manual verification before a release.)

---

## Things that look like bugs but aren't

- **`asyncio.create_task` and the test client.** When a route fires a
  background graph task, the test's `client` fixture's lifespan exits
  before the task finishes. The R2 e2e tests work around this by
  calling `run_one` directly rather than going through the route —
  proves the graph, skips the dispatch dance.
- **Truncate-everything fixture.** Tests assume an empty DB. If you're
  poking with `psql` between tests, expect surprises.
- **Redis deprecation warnings.** redis 5.x complains about
  `close()` vs `aclose()`. We use `aclose()` with a `# type: ignore`;
  the bundled types lag.
