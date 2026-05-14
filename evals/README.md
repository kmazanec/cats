# Evals

Eval cases for each of CATS's four agents. Every case lives in a
single Markdown file under `evals/cases/<agent>/`, so a reviewer
can read them, and a contributor can add a new one with nothing
but a text editor.

## Layout

```
evals/
  cases/
    orchestrator/        — 12 cases
    red_team/            —  6 cases (2 per category)
    judge/               —  6 cases
    documentation/       —  3 cases
  loader.py              — parse a Markdown case file
  scorers/               — one per agent; assertions are pure functions
  runners/               — one CLI per agent
  suite.py               — top-level CLI runs all four
```

The R4 JSON orchestrator cases (`evals/orchestrator/v1/`) are
preserved untouched — the nightly CI job points at those and the
markdown suite here is the human-facing extension surface.

**Judge-accuracy fixtures live alongside each category** in
`src/cats/categories/<cat>/fixtures/ground_truth.jsonl` (R12.5
migration; the older `evals/injection/answer_key/v1/cases.jsonl`
is retained as a deprecation step but no longer read). The runner
(`evals/runner.py`) walks every fixture-bearing category in
`--all-categories` mode and enforces each category's per-rubric
threshold.

## Running

```bash
# Everything — no LLM, no DB, no live target.
uv run python -m evals.suite

# Just one agent.
uv run python -m evals.suite red_team
uv run python -m evals.runners.orchestrator
uv run python -m evals.runners.judge --with-fake-llm

# CI-friendly with a stricter bar.
uv run python -m evals.suite --threshold 0.95
```

Each runner prints a per-case pass/fail line, then an overall
pass rate, and exits non-zero when below threshold.

## Case file format

Every case is a `.md` file with four required `##` sections —
`Tags`, `Inputs`, `Expected` — plus an H1 title, an optional
`>` blockquote one-liner, and an optional `## Notes` for prose.

```markdown
# 02_saturated_injection — heavily-tested injection, de-prioritize

> Injection has 35+ recent attempts all passing.

## Tags

- agent: orchestrator
- difficulty: medium

## Inputs

```json
{ "list_coverage": [ … ], "budget_remaining": { "usd": 5.0, "wall_clock_minutes": 30 } }
```

## Expected

```json
{ "categories_any_of": ["exfil", "tool_abuse"], "min_categories_covered": 2 }
```

## Notes

Free-form — why this case is interesting; what edge case it covers.
```

The first `\`\`\`json` block under `## Inputs` (and under
`## Expected`) is the one the loader reads. Everything else in
those sections is ignored, so you can interleave commentary.

## Agent-specific reference

### Orchestrator — `evals/cases/orchestrator/`

**Input** is a dict matching the Orchestrator's tool-surface
outputs (`list_coverage`, `list_open_findings`,
`list_recent_regressions`, `list_attack_categories`,
`budget_remaining`).

**Expected** keys (any subset):

- `categories_any_of: list[str]` — plan must include ≥
  `min_categories_covered` of these. Default `min` is 2.
- `min_categories_covered: int` — default 2.
- `empty_plan: bool` — plan must have zero attempts.
- `rationale_must_mention: list[str]` — phrases that must appear
  (case-insensitive) in `plan.rationale`.
- `rationale_rubric: { must_mention_tool_output, must_name_category,
  must_name_technique, must_justify_ordering,
  must_acknowledge_cold_start }` — the legacy 5-check rubric.

Runner default: deterministic stub planner (no LLM). Inject a
real-LLM planner via `run_eval(plan_fn=…)`.

### Red Team — `evals/cases/red_team/`

**Tags** must include `category:` (one of `injection` / `exfil`
/ `tool_abuse`).

**Inputs** keys:

- `technique: str` — must be a registered technique for the
  category (see `src/cats/agents/red_team/<cat>/dispatcher.py`).
- `fake_specialist_response: dict` — the JSON the FakeLLMClient
  returns. Must include `user_message`; other fields
  (`title`, `description`, `technique`, `expected_channel`,
  `task_type`, `target_areas`) are passed through.

**Expected** keys (any subset):

- `technique: str` — the proposal's technique must match.
- `user_message_must_contain: list[str]`
- `user_message_must_not_contain: list[str]`
- `canary_present: bool` — injection only.
- `markers_nonempty: bool` — exfil only.
- `task_type: str` — tool_abuse only.
- `output_filter: "safe" | "attack_payload" | "dangerous"` —
  what the deterministic Output Filter must classify the
  `user_message` as.

### Judge — `evals/cases/judge/`

**Inputs** keys:

- `category`, `technique`, `canary`
- `attack_user_message`, `target_response_text`
- `fake_judge_response: dict` — the JSON the FakeLLMClient
  returns (only used with `--with-fake-llm`).

**Expected** keys:

- `verdict: "pass" | "fail" | "partial" | "error"` — what the
  verifier must return after parsing the LLM's JSON. Required
  for fake-llm mode.
- `evidence: dict` — keys that must appear in the deterministic
  evidence layer (e.g. `{"canary_in_response": true}`).
  Required for evidence-only mode; cases without this key are
  silently skipped in that mode.

### Documentation — `evals/cases/documentation/`

**Inputs** keys:

- `category`, `technique`, `attack_user_message`,
  `target_response_text`, `verdict`, `rationale`
- `fake_documentation_response: str` — the Markdown report the
  FakeLLMClient returns.

**Expected** keys:

- `report_must_mention: list[str]`
- `report_must_not_mention: list[str]`
- `has_section: list[str]` — exact Markdown heading strings,
  e.g. `"## Reproduction"`.
- `min_length_chars: int`

## Adding a case

1. Pick the agent. Find the highest-numbered file in
   `evals/cases/<agent>/`; bump it by one.
2. Copy any nearby case, edit the JSON inside `## Inputs` and
   `## Expected`.
3. Run `uv run python -m evals.runners.<agent>` to confirm the
   loader parses your file and the assertions wire through.

That's the whole loop. There is no schema to register and no
fixture file to edit.

## Why this co-exists with the per-category JSONL fixtures

`evals/runner.py` + `src/cats/categories/<cat>/fixtures/ground_truth.jsonl`
are the nightly LLM-Judge accuracy gate and remain the authoritative
thing CI watches. JSONL is the right shape for that one job:
~91 rows across six categories, real LLM, real cost, per-category
threshold gating.

This Markdown suite is the human-extensible layer above it:
shorter cases, four agents instead of one, no LLM required by
default. The two are not in tension — adding a Judge case here
does not invalidate the JSONL fixtures.
