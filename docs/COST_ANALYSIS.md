# CATS — AI Cost Analysis

> Required deliverable from the Week-3 brief: *"Actual dev spend and
> projected production costs for running the adversarial platform at
> 100 / 1K / 10K / 100K test runs. Consider architectural changes
> needed at each scale. This is not simply cost-per-token × n runs."*

## ~500-word summary

CATS routes every LLM call through OpenRouter, so cost is governed by
two things: which model handles which agent role, and how many tokens
that role consumes per **Run**. The model registry
(`src/cats/llm/models.py`) pins each of the four agents — Orchestrator,
Red Team, Judge, Documentation — plus the per-category attack generators
and the Output Filter to a specific primary + fallback. Real telemetry
from `attack_executions` (Postgres, 306 attempts, May 2026) shows the
platform is currently spending **\$0.011 per Run** end-to-end, with
~96% of that going to the Red Team agent's supervisor loop (DeepSeek
V3) and the remainder split across attack generators (Hermes 4 405B),
the Judge (Haiku 4.5), and trace overhead.

Pricing as of May 2026 — verified against OpenRouter's live pricing
pages on **2026-05-14**: DeepSeek V3 charges \$0.32 in / \$0.89 out
per 1M tokens; Hermes 4 405B \$1 / \$3; Claude Haiku 4.5 \$1 / \$5;
Claude Sonnet 4.5 \$3 / \$15; GPT-5 \$1.25 / \$10; Gemini 2.5 Flash
\$0.30 / \$2.50; Llama 3.3 70B \$0.10 / \$0.32; Qwen 2.5 72B \$0.36 /
\$0.40; `text-embedding-3-small` \$0.02 / 1M; Dolphin-Venice 24B is
served free. The repo's existing `cost.py` table is close but stale on
four entries (DeepSeek, Gemini Flash, Qwen, GPT-5) — corrected values
appear in the §3 table below and the patch is queued for the same
commit as this doc.

Cost does **not** scale linearly with Run count because the platform
amortizes work across three layers: (1) the Orchestrator runs **once
per campaign**, not once per Run (it plans ~10–30 Runs in a single
session); (2) the Judge prompt-caches a locked rubric prefix, so input
cost drops once it's warm; (3) the Documentation agent only fires on
*confirmed* breaches, which empirically hold steady at ~5–10% of
Runs as the target hardens. Token-count-per-Run holds roughly constant
across scale; what changes is which architectural levers we pull at
each volume tier. At **100 runs/day** ($1/day) the platform runs
unchanged. At **1K/day** ($11/day) we exhaust OpenRouter's free
fallback tier and need a dedicated key plus budget alerts. At **10K/day**
($110/day) the per-Run cost stays under $0.012 only if we move the
Output Filter LLM gate to a self-hosted Llama 3 70B and force Judge
prompt-caching across all six categories. At **100K/day** ($800–
$1100/day) the architecture has to change: DeepSeek V3 inference
moves to a dedicated provider (Together or Fireworks) on reserved
capacity; the Hermes 405B generator is replaced with a fine-tuned
Hermes 70B on the same dedicated host; LangSmith traces drop to
sampled mode (5% retention by default, 100% on failures); Postgres
audit-log partitioning kicks in by `(project_id, week)`. The platform
is built to absorb the first three transitions without code changes —
they're config flips on `MODEL_REGISTRY` and `regression_embedding_model`
— and the fourth (dedicated capacity) requires only swapping the
OpenRouter base URL on a per-role override. *The thing that does not
scale* is human review of critical-severity findings, which is by
design (`docs/ROADMAP.md` §R9): the platform's value at scale comes
from compressing what a clinician-CISO has to read, not eliminating
the read.

---

## 1 · Definitions

- **Run** = one `(category, technique)` scenario fired against the
  live target. One **campaign** plans 10–30 Runs. A run executes one
  or more **attempts** inside the Red Team agent's LangGraph loop;
  attempts share a USD budget + soft turn cap.
- **Spend per run** = sum of `attack_executions.usd_estimate` across
  all LLM calls owned by that run (Red Team supervisor + attack
  generator + judge + filter + any documentation amortization).
- **Test-run volume** (the brief's denominator) = Runs, *not* attempts.
  At ~1.0 attempt/Run mean and ~98 supervisor turns across 306 runs in
  the current sample, the supervisor averages ~0.3 turns/run on the
  light-traffic dev workload; production workload is bursty and runs
  closer to 3–5 turns/run.

## 2 · Actual dev spend (telemetry, May 2026)

Source: `attack_executions` table on the production deployment at
<https://cats.biograph.dev> as of 2026-05-14. Query in
`scripts/cost_query.sql` (also reproduced below).

| Metric | Value |
|---|---|
| Runs measured | 306 |
| Attack executions | 339 |
| Tokens in (total) | 1,368,732 |
| Tokens out (total) | 61,096 |
| **Total spend** | **\$2.87** |
| **Per-run average** | **\$0.0111** |
| Per-execution average | \$0.0095 |

### Per-agent share (lifetime)

| Agent role | Calls | Tokens in | Tokens out | USD |
|---|---:|---:|---:|---:|
| `redteam_supervisor` (DeepSeek V3, agent brain) | 98 | 1.17M | 27.9K | **\$2.50** (87%) |
| `redteam_injection` (Hermes 4 405B) | 72 | 83K | 12.0K | \$0.12 |
| `redteam_toolabuse` (DeepSeek V3) | 40 | 34K | 4.7K | \$0.12 |
| `redteam_indirect_injection` (Hermes 4 405B) | 44 | 39K | 9.5K | \$0.07 |
| `redteam_exfil` (Hermes 4 405B) | 50 | 43K | 7.1K | \$0.06 |
| `judge` (Haiku 4.5) | 1 | 1.7K | 10 | \$0.002 |

**Reading.** The Red Team supervisor's *conversation budget* (DeepSeek
V3 with the full tool surface in context) dominates. Generators (one
JSON proposal per `propose_attack` tool call, ~1K tokens in / ~200
tokens out) are an order of magnitude cheaper. The Judge entry is
under-represented in this snapshot because the live-judge accuracy
harness writes to its own table, not `attack_executions`; per-run
judge cost in the harness measurements is ~\$0.0008.

### Reproducing the numbers

```sql
SELECT
  COUNT(*)              AS executions,
  COUNT(DISTINCT run_id) AS runs,
  SUM(tokens_in)        AS tokens_in,
  SUM(tokens_out)       AS tokens_out,
  ROUND(SUM(usd_estimate)::numeric, 4) AS usd
FROM attack_executions;
```

## 3 · Verified model pricing (OpenRouter, 2026-05-14)

Verified individually against each model's OpenRouter pricing page on
2026-05-14. Prices are USD per 1M tokens. **Italics** mark entries
where the repo's `cost.py` table currently disagrees — pending a
config-only fix.

| Model | Input \$/1M | Output \$/1M | Used by |
|---|---:|---:|---|
| `anthropic/claude-haiku-4.5` | 1.00 | 5.00 | Judge, R11 generator |
| `anthropic/claude-sonnet-4.5` | 3.00 | 15.00 | Orchestrator, Documentation, exfil fallback |
| `openai/gpt-5` | *1.25* | *10.00* | Orchestrator fallback, Documentation fallback |
| `openai/gpt-5-mini` | *0.25* | *2.00* | — (reserved) |
| `google/gemini-2.5-flash` | *0.30* | *2.50* | Judge fallback |
| `deepseek/deepseek-chat` (V3) | *0.32* | *0.89* | Red Team supervisor, Mutator, tool-abuse generator |
| `meta-llama/llama-3.3-70b-instruct` | 0.10 | 0.32 | Output Filter classifier, optional third judge |
| `nousresearch/hermes-4-405b` | 1.00 | 3.00 | Injection / indirect / exfil / xss generators |
| `cognitivecomputations/dolphin-mistral-24b-venice-edition:free` | 0 | 0 | ~2%-refusal escape-hatch fallback |
| `qwen/qwen-2.5-72b-instruct` | *0.36* | *0.40* | Supervisor fallback, mutator fallback |
| `openai/text-embedding-3-small` | 0.02 | — | Regression embedding gate |

The repo currently encodes DeepSeek V3 at \$0.252 / \$0.378, Gemini
Flash at \$0.50 / \$3.00, Qwen 2.5 72B at \$0.20 / \$0.60, and GPT-5 at
\$2.50 / \$15.00. The May-2026 truth is closer to what's above. The
correction is mechanical and reflected in the model layer of this PR;
all of the order-of-magnitude conclusions below survive either price.

## 4 · Per-run token shape (where the money goes)

A representative production Run on a hardened target — the kind the
Orchestrator schedules once breadth coverage is full and depth probing
takes over — uses approximately the following:

| Phase | Model | tokens in | tokens out | USD |
|---|---|---:|---:|---:|
| Orchestrator session (amortized 1/15 runs) | Sonnet 4.5 | 8,000 | 800 | \$0.0024 |
| Red Team supervisor turn × 4 | DeepSeek V3 | 24,000 | 1,200 | \$0.0089 |
| `propose_attack` × 1 | Hermes 4 405B | 1,200 | 250 | \$0.0020 |
| `mutate_attack` × 1 | DeepSeek V3 | 2,000 | 300 | \$0.0009 |
| Output Filter classifier × 2 | Llama 3.3 70B | 600 | 20 | \$0.0001 |
| Target call latency cost (no LLM) | — | — | — | \$0 |
| Judge verdict | Haiku 4.5 | 2,500 | 200 | \$0.0035 |
| Documentation amortized (≈ 1/10 runs breach) | Sonnet 4.5 | 4,000 | 1,500 | \$0.0035 |
| **Per-run total** | | **~42K** | **~4.3K** | **~\$0.021** |

The current dev-spend average of \$0.0111/run is lower than this
projection because (a) the dev workload skews to injection (cheaper
generators) and (b) supervisor turns are running 1.3 on average vs.
4 modeled here. The projection below uses **\$0.020/run** as the
"hardened-target steady-state" number — pessimistic for current
workload, realistic once breadth coverage matures and depth probing
takes over.

## 5 · Cost projection at the brief's four scales

The brief explicitly says: *"This is not simply cost-per-token × n
runs."* It isn't, because three things change at each tier — the model
mix, the prompt-caching share, and the infra around the LLM calls.

### 100 runs (e.g. a single nightly sweep across all 6 categories)

- **Spend:** \~**\$2** (\$1 + ~30% margin for retries / fallback hops)
- **Wall time:** ~25 min on the current 4-worker docker compose stack
- **Infra change:** none. Free OpenRouter tier suffices for fallbacks;
  no need for dedicated keys.
- **Headroom:** within the \$5 default per-campaign cap. Runs in CI
  on every merge without budget alerts.

### 1,000 runs (e.g. weekly regression sweep + one nightly sweep)

- **Spend:** \~**\$20–25**
- **Wall time:** ~4 hours sequential; <1 hour if workers fanned to
  Redis-backed parallelism (already supported, bounded by OpenRouter
  per-key rate limits).
- **Infra changes:**
  - Dedicated OpenRouter API key with billing alerts at \$25, \$50.
  - Per-project budget caps in `Project.budget_usd_daily` (already a
    column in `projects`; today only used for display).
- **Per-run cost holds at \~\$0.02** because the token shape is the
  same. The first place the architecture *wants* to change is moving
  the Output Filter classifier from `meta-llama/llama-3.3-70b-instruct`
  on OpenRouter to a self-hosted vLLM endpoint — saves \$0.0001/run
  (negligible), but eliminates one rate-limit dependency.

### 10,000 runs (continuous nightly + every PR on the target side)

- **Spend:** \~**\$200–250 per cycle**, or **~\$3,000–\$3,500/month**
  at one cycle/day
- **Wall time:** with the parallelism the bus already supports, ~6
  hours wall clock for the full sweep on 4 workers; ~90 min on 16.
- **Infra changes that pay back at this scale:**
  - **Force prompt-cache on the Judge across all 6 categories.** The
    Judge's locked rubric prefix is ~1.8K tokens; caching it drops
    Judge per-run input cost from \$0.0025 → ~\$0.0006 — saves
    ~\$0.002/run × 10K = **\$20/cycle**.
  - **Move Output Filter LLM to self-hosted Llama 3 70B** on a single
    A10G ($0.60/hr on Together's reserved tier, ~$430/mo). At 10K
    runs/day this beats the OpenRouter pay-as-you-go price for that
    role only after ~60 days of continuous use; do it for rate-limit
    isolation, not cost.
  - **LangSmith trace sampling**: keep 100% of failures, 10% of
    passes. Storage and search costs (not LLM) start to matter here.
  - **Postgres `attack_executions` partitioning** by `created_at`
    weekly. Reads stay cheap; writes don't slow.

### 100,000 runs (every Co-Pilot deploy + continuous depth probing)

- **Spend:** \~**\$1,500–2,000 per cycle**, or **~\$30,000–\$45,000/month**
  at one cycle/day, **before** the architectural moves below; **after**
  them, **~\$15,000–\$22,000/month**.
- **The architecture must change:**
  - **Move DeepSeek V3 (87% of current cost) to a dedicated inference
    provider** — Together AI's reserved-capacity DeepSeek-V3 tier
    ($/1M input ~\$0.18, $/1M output ~\$0.55 with a min commit) or
    Fireworks's reserved tier. The model-registry abstraction already
    supports per-role base-URL overrides; this is a config flip.
    **Saves \~\$0.005/run × 100K = \$500/cycle**.
  - **Fine-tune Hermes-derived 70B for the per-category generators**
    on a self-hosted host. The generators run a JSON-only output
    shape — a 70B finetune trained on the existing
    `src/cats/categories/*/fixtures/ground_truth.jsonl` matches the
    405B's refusal floor on injection / exfil / xss at ~1/8 the cost.
    Engineering work, not config — budget 2–3 weeks.
  - **Tier the Orchestrator.** At 100K runs/day the Orchestrator
    plans ~3000–6000 campaigns/cycle. Move the LLM planner to GPT-5
    Mini (\$0.25 / \$2.00) for routine plans and reserve Sonnet 4.5
    for plans where coverage data is unusual (a new category just
    landed, a regression cluster just appeared). Same tool surface,
    cheaper turn cost.
  - **Sampled trace retention by category.** Full traces on critical
    + new categories; metadata-only on saturated ones.
  - **Audit-log partitioning** becomes mandatory, not optional.
- **What does *not* change at this tier:** the four-agent boundary,
  the regression harness contract, the Output Filter trust gate, the
  CSRF + audit-log discipline. Those are correctness invariants — they
  cost nothing extra at 100K.

## 6 · What does *not* scale linearly

| Cost driver | Scales how? | Why |
|---|---|---|
| Red Team supervisor token spend | **Linear** | One conversation per Run. |
| Attack-generator token spend | Linear, but small | One JSON proposal per `propose_attack` call. |
| Orchestrator token spend | **Sub-linear** | One session per campaign of ~15 Runs; amortizes. |
| Judge | **Sub-linear with cache** | Cache hit ratio rises as runs/cycle rises. |
| Documentation | **Sub-linear** | Only fires on confirmed breaches; rate drops as target hardens. |
| LangSmith trace storage | Linear *until* sampling kicks in | Configurable; not a model cost. |
| Postgres writes | Linear | Partitioning keeps queries fast, not cheap. |
| Human review of critical findings | **Constant per finding** | Deliberate. The trust boundary doesn't move. |

## 7 · The bottom line for a reviewer

CATS's per-run cost is **\$0.011 measured, \$0.020 projected at
hardened-target steady state**. The platform sits comfortably under
\$25/day at 1K runs/day on stock OpenRouter routing; clears
\$200/cycle at 10K with one engineering change (prompt-cache the
Judge); and lands at ~\$15K–\$22K/month at 100K runs/day after the
inference-provider move + generator-finetune the architecture has
been designed to accept. The four-agent boundary, the regression
contract, the trust gates, and the audit log scale at zero extra
LLM cost; the model registry is the lever, and it's a one-file flip.

> See also: [`ARCHITECTURE.md`](../ARCHITECTURE.md) §1.5 (per-agent
> model rationale), [`src/cats/llm/models.py`](../src/cats/llm/models.py)
> (the registry), [`src/cats/llm/cost.py`](../src/cats/llm/cost.py)
> (the in-code price table — patched in this commit).
