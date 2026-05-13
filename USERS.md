# Users — CATS

> **CATS — Copilot Automated Tactical Security.** This document
> identifies the users CATS serves, walks through how each one uses
> the platform, and explains why automation is the right solution
> for the problem CATS solves.
>
> **Companions:**
> - [`ARCHITECTURE.md`](./ARCHITECTURE.md) — platform architecture
> - [`THREAT_MODEL.md`](./THREAT_MODEL.md) — target-system threat model
> - [`docs/W3_THREAT_RESEARCH.md`](./docs/W3_THREAT_RESEARCH.md) — May-2026 attack-landscape research

---

## Executive summary

CATS serves three users with distinct workflows but a shared
underlying need: **continuously knowing whether the OpenEMR
Clinical Co-Pilot is improving or regressing under adversarial
pressure.** The **AI / Security Engineer** is the daily driver —
they fire campaigns, approve the Orchestrator's per-campaign
plans before dispatch, triage findings, validate fixes, and
curate the rubrics and fixtures that govern what counts as an
exploit.
**Engineering Leadership / CISO** consumes coverage dashboards,
approves critical-severity findings, and owns the platform's
authority to run against production. **External Red-Team
Contributors** extend CATS with new attack categories,
testing-time variants, and category-specific Judge rubrics; they
operate at the periphery, not in the daily loop.

The work these users do exists today — it just doesn't scale. A
hospital-grade AI red team running quarterly engagements at
$50K-$200K each cannot keep pace with a target system whose model,
prompts, and tools evolve weekly. The May-2026 research is
unambiguous: 12 of 12 published defenses against indirect prompt
injection were bypassed at >90% ASR by frontier labs themselves;
NCSC formally classified prompt injection as "unsolved"; indirect
injection via documents now drives >55% of observed LLM attacks.
A static test suite ages out in weeks. Manual review cannot
generate ten variants of a partially-successful attack to find the
one that breaks through. The work the users above need to do is
*structurally* a continuous, mutation-driven, evaluation-heavy
loop — exactly the shape automation is best at.

CATS is not a replacement for human security engineers; it is
their **continuously-running force multiplier.** Engineers still
own the categories, the rubrics, the trust boundaries, and the
critical-severity gate. CATS executes the inner loop they would
otherwise have to drive by hand: generate, mutate, evaluate,
prioritize, document, and re-test as the target evolves. The
sections below walk through each persona's workflow with the
specific use cases that justify this division of labor.

---

## Why automation is the right solution

The brief asks for **explicit justification** that automation is
the right tool here, not just convenient. Four arguments:

### 1. The target moves faster than human review can

OpenEMR's Clinical Co-Pilot is under active development. New
tools land, prompts get tuned, models get upgraded, document
extractors get extended. Any one of those changes can reopen a
previously-fixed vulnerability or introduce a new one. The
relevant question is not "does the co-pilot have vulnerabilities
today" but **"is each release safer or less safe than the one
before."** A quarterly pen-test produces a single
point-in-time answer; CATS produces release-over-release deltas.

### 2. The attack surface is mutation-shaped

The May-2026 research (see [`docs/W3_THREAT_RESEARCH.md`](./docs/W3_THREAT_RESEARCH.md))
documents that successful attacks against LLMs rarely arrive
as a single static payload. They arrive as **a partially-successful
attempt, then nine variants of it.** Crescendo bypasses Claude
in fewer than five turns of benign-looking escalation. Policy
Puppetry, Bad Likert Judge, and Many-Shot Jailbreaking all
require iteration on a *theme*, not a single payload. The
[`Mutator`](./ARCHITECTURE.md#21-agent-roster) agent exists
precisely because variant generation is the bottleneck for human
red-teams and the comparative advantage of LLMs.

### 3. Reproducibility cannot be human-mediated

The brief explicitly warns: "A test that passes because the
model's behavior changed — not because the vulnerability was
actually fixed — is worse than no test at all." Distinguishing
"genuinely fixed" from "just refuses differently now" requires
the **triple gate** described in [`ARCHITECTURE.md` §3.4](./ARCHITECTURE.md#34-regression-suite-pass-criterion):
deterministic post-condition, locked-version Judge verdict, and
behavioral-fingerprint embedding-distance match. A human engineer
cannot run those three checks against every regression case after
every release. Automation can.

### 4. Evidence quality scales with coverage

When the AI Security Engineer triages a finding, the question
they need to answer is "is this real, and how does it relate to
the other 47 findings we have open?" That coordination cost grows
super-linearly with finding count and is exactly the work a
shared schema — every Finding labeled with its MITRE ATLAS
technique, its OWASP LLM Top 10 ID, its severity, its
exploitability axis — is built for. A manual red team produces
prose reports that take human effort to cross-reference. CATS
produces structured findings the [`Documentation
Agent`](./ARCHITECTURE.md#21-agent-roster) writes against a
schema, queryable by every persona below.

**The work is structurally automatable. The work is structurally
unmanageable at scale by humans alone. Both are true. CATS is
where they meet.**

---

## Persona 1 — AI / Security Engineer (primary)

**Profile.** A senior engineer at OpenEMR with security background
and working familiarity with the Clinical Co-Pilot's internals.
Owns the day-to-day operation of CATS: when to run campaigns,
which findings warrant a fix, which fixtures to add, which
specialist prompts to revise. **Sits at the plan-approval gate
before every campaign** — reads the Orchestrator's proposed plan
and rationale, edits or rejects when it disagrees, approves when
the plan makes sense. Reads Postgres tables directly when the
dashboard isn't enough. Pages the on-call dashboard at the start
of every clinical-AI release window.

**Tools they reach for.** CLI for ad-hoc campaigns; web dashboard
for plan approval and triage; LangSmith for drill-down on
inter-agent traces; Postgres directly for queries the dashboard
doesn't surface yet.

**What they care about.** Low false-positive rate (their time is
finite); plans that read as informed by real coverage state, not
boilerplate; fast feedback when a fix lands; replayability of
every finding from the trace alone; the ability to add a new
category without touching shared dispatch code.

### Use case 1.1 — *Run a campaign against the live target*

The engineer wants to know what CATS finds today. They open the
CLI or dashboard, select the relevant Project (the deployed
co-pilot URL), and fire a campaign with just two inputs: the
target and a budget cap. They do **not** name a category or a
technique — that is the
[`Orchestrator`](./ARCHITECTURE.md#21-agent-roster)'s job.

The Orchestrator reads the project's current state through its
tool surface (per
[`ARCHITECTURE.md` §2.4](./ARCHITECTURE.md#24-orchestrator-policy):
`list_coverage`, `list_open_findings`,
`list_recent_regressions`, `list_attack_categories`,
`budget_remaining`) and authors a structured `CampaignPlan` — an
ordered list of `(category, technique)` attempts with
per-attempt budgets, halt conditions, and a paragraph of
rationale grounded in those tool outputs. The plan lands in the
dashboard awaiting the engineer's review.

**This is where the engineer's judgment lives.** They read the
rationale ("`system_prompt_leak` hasn't been tested in 30 days;
the recent `policy_puppetry` finding suggests the system-prompt
isolation is weak; prioritize SPE-LLM"), agree or disagree, and
either approve the plan, edit it (drop a technique, add one,
reorder, change a budget), or reject it back to the
Orchestrator. The diff between the proposed plan and the
approved plan is recorded against the engineer in the audit log.

Once approved, the campaign dispatches. The [`Red Team
Router`](./ARCHITECTURE.md#21-agent-roster) executes the plan's
attempts — it is the *executor*, not the *picker* — invoking
each specialist named in the plan; the specialist generates
attacks; the
[`Mutator`](./ARCHITECTURE.md#21-agent-roster) iterates on
partial successes; the
[`Judge`](./ARCHITECTURE.md#25-judge-integrity) verifies; the
[`Documentation
Agent`](./ARCHITECTURE.md#21-agent-roster) writes findings to
Postgres. The engineer watches the live dashboard, sees the
current attempt and verdict, sees the running cost, and stops
the campaign early if the signal is clear before the budget
exhausts.

**Why automation here, and why the human gate.** Generating
thousands of attack variants across categories, evaluating each
against a per-category rubric, and persisting structured
Findings to a queryable store is purely mechanical work that a
human would do either badly (skip steps, forget verdicts, lose
evidence) or slowly (one attack every few minutes, no
parallelism). What is *not* mechanical is **deciding what to
test next** — that decision benefits from reasoning over the
project's state, which is the Orchestrator's job, but it also
benefits from a sanity check by someone who knows the project,
which is the engineer's. The plan-approval gate is the brief's
"where does your system stop and ask a human" boundary for the
strategic layer; the critical-finding gate (Use case 2.2) is the
other one. The system runs autonomously *within* an approved
plan; it does not autonomously decide what to run.

### Use case 1.2 — *Triage a high-severity finding*

A finding lands in the dashboard with severity `high` and
exploitability `confirmed`. The engineer opens it. The dashboard
shows the attack payload, the target response, the Judge's
verdict with the rubric version that produced it, the
deterministic post-condition that fired (canary token leaked,
audit log violation, etc.), and a deep link to the LangSmith
trace. The engineer reads the trace to understand what the model
actually did, decides the finding is real, assigns severity-confirmed,
and routes it to the co-pilot team's tracking system. They mark
the finding as **eligible for regression** so the case enters the
regression harness.

**Why automation here.** Without CATS, this triage would require
the engineer to *reproduce* the attack manually, which means
re-deriving the exact attack payload, re-establishing the
test environment, and re-running the live target. With CATS,
reproduction is a one-click "replay" against the persisted attack
+ trace ID. The engineer's time goes to *judgment*, not to
re-execution.

### Use case 1.3 — *Validate a fix*

The co-pilot team ships a patch claiming to address a previously
confirmed finding. The engineer opens the finding in the
dashboard, clicks "re-run regression," and CATS executes the
attack against the now-redeployed target. The
[`Judge`](./ARCHITECTURE.md#25-judge-integrity) runs the **triple
gate**: deterministic post-condition does not fire, the
locked-version rubric still returns `fail`, and the behavioral
fingerprint matches the captured refusal exemplar. If all three
pass, the finding is marked `fixed`. If any one fails, the finding
is **escalated for human review** rather than auto-promoted — this
is the brief's "the model just refuses differently now" hazard
made explicit. The engineer decides whether the failed gate is a
real regression or a legitimate behavioral change, and updates the
exemplar accordingly.

**Why automation here.** The triple gate is too tedious to run by
hand against every regression case after every release. A manual
process either skips one of the three gates (and misses real
regressions) or skips re-running regressions entirely (and ships
bugs the fix didn't actually fix). Both failure modes are the
ones the brief explicitly warns about.

### Use case 1.4 — *Add a new attack category*

The threat-research literature surfaces a new attack technique.
The engineer drops a new directory under `cats/categories/<name>/`
containing a manifest, the specialist's system prompt and
few-shot examples, the locked rubric, hand-labeled ground-truth
fixtures, and the deterministic post-condition (canary check,
audit-log check, etc.). They register the category in the
category index. The
[`Red Team Router`](./ARCHITECTURE.md#21-agent-roster) picks it
up automatically; the next campaign can target it; the
Orchestrator's `list_attack_categories` tool now surfaces the
new category to the planner, which sees it as zero-coverage and
typically prioritizes it for the next campaign's plan — visible
to the engineer in the plan's rationale before it dispatches.

**Why automation here.** The plugin contract is what makes the
new category usable across thousands of attack iterations
*today*, not just available for the engineer to run by hand.
Without the contract, every new category would mean code changes
in the dispatcher, the Judge, the Documentation Agent, the
dashboard. With it, a new category is one PR that's review-able
as a unit.

---

## Persona 2 — Engineering Leadership / CISO (secondary)

**Profile.** A senior engineering leader or hospital CISO
responsible for the safety posture of the AI features in
OpenEMR. Not a daily user of CATS' internals. Reads dashboards
weekly. Owns the platform's authority to run against production
targets. Approves any finding rated `critical` before it becomes
a remediation ticket.

**Tools they reach for.** Web dashboard only. They do not use the
CLI. They do not read LangSmith traces directly.

**What they care about.** Coverage trend over time; open findings
by severity; the platform's running cost; the audit log of who
ran what against which target; the comparison between black-hat
and white-hat finding counts (see [`ARCHITECTURE.md`
§5a](./ARCHITECTURE.md#5a-dual-mode-attack-vision--black-hat-and-white-hat)).

### Use case 2.1 — *Review coverage at a release window*

The OpenEMR co-pilot team is preparing a release. Leadership
opens the CATS dashboard's coverage matrix view. They see, per
attack category, how many tests have run against the upcoming
release-candidate target, the pass/fail/partial breakdown, the
trend versus the previous release, and the count of open findings
by severity. They see, in the side panel, three findings escalated
to `critical` and awaiting their approval. They review each,
approve two for the remediation queue, and send the third back
to the engineer for a second look.

**Why automation here.** The coverage matrix is updated
continuously by Postgres rollups from the Documentation Agent's
writes. Manually constructing this view from quarterly pen-test
reports is impossible — the data does not arrive on a release
cadence. CATS makes the coverage view *contemporaneous* with the
release decision.

### Use case 2.2 — *Approve a critical-severity finding*

A finding hits the `critical` severity threshold based on its
Likelihood × Impact score and the rubric-version-locked Judge
verdict. The
[`Documentation Agent`](./ARCHITECTURE.md#21-agent-roster) pauses
before writing the finding's status as `confirmed-and-tracked` —
this is the **trust boundary** the brief explicitly asked us to
design. Leadership receives a notification (email or Slack
depending on configuration), opens the finding in the dashboard,
reads the attack payload + target response + Judge verdict + trace
deep-link, and either approves or rejects. The approval is
recorded against the finding's trace ID in the audit log. Only
approved critical findings become remediation tickets.

**Why automation here.** The platform produces the structured
evidence; the human makes the judgment call. This is the correct
division of labor for an action with high blast radius and
ambiguous severity.

---

## Persona 3 — External Red-Team Contributor (secondary)

**Profile.** A security researcher external to the OpenEMR core
team. Hired periodically for deep-dive engagements; familiar with
adversarial AI testing methodology; contributes new attack
categories, technique variants, or rubric improvements based on
research the OpenEMR team hasn't yet seen.

**Tools they reach for.** Git (PRs to the `cats/categories/`
plugin contract); a sandbox Project to test their category in
before promoting to a production-target campaign.

**What they care about.** A clear plugin contract; the ability to
test their category in isolation; no privileged access to other
categories' rubrics or to production finding data they shouldn't
see.

### Use case 3.1 — *Contribute a new category*

The contributor reads a new arXiv paper on a previously-undocumented
LLM attack technique. They fork CATS, add a `cats/categories/<name>/`
directory matching the plugin contract (manifest, specialist
prompt, rubric, fixtures, deterministic post-condition), and open
a PR. The OpenEMR engineer (Persona 1) reviews the category
against the existing rubrics and the May-2026 research, runs the
category in a sandbox Project to verify the fixtures produce the
expected Judge verdicts, and merges. The contributor's category
becomes visible to the Orchestrator's `list_attack_categories`
tool on the next campaign; Persona 1 sees it surface in the
proposed plan and approves the first live run.

**Why automation here.** The contract is the contract precisely
because it lets contributors extend CATS without needing global
knowledge of dispatch logic, schema details, or the dashboard.
Manual onboarding of contributors at the code level wouldn't
scale beyond one or two contributors. Plugin-style extensibility
is *itself* an automation feature.

---

## Who CATS is **not** for

Explicitly out of scope. These are not gaps to fill in v2 — they
are deliberate boundaries the platform respects.

### Not for clinicians directly

CATS does not interact with the clinicians who use the
co-pilot. It runs *against* the co-pilot, not *for* its users.
A clinician seeing a co-pilot misbehave reports it through
OpenEMR's normal feedback channel; if the report represents a
new attack category, the engineer (Persona 1) adds a category
plugin and a regression fixture. The clinician is not a CATS
user.

### Not a SOC / real-time monitoring tool

CATS does not monitor production traffic for live attacks. It
*generates* attack traffic in controlled, audited campaigns
against allow-listed Project targets. A SOC tool watches the
real world; CATS adversarially probes a defined system under
test. Confusing the two leads to wrong expectations on both
sides.

### Not a vulnerability scanner for non-LLM surfaces

CATS does not test OpenEMR's REST APIs, its PHP layer, its
authentication infrastructure, or any other non-LLM surface
except insofar as those surfaces *interact* with the co-pilot
(e.g., the `promote.php` write path is in scope only because
the co-pilot's `accept_fact` flow uses it). Traditional
application-security tools cover the rest.

### Not a model-quality / benchmarking tool

CATS does not measure the co-pilot's accuracy on benign
clinical tasks, its latency, or its UX. Those are
model-quality concerns measured by the co-pilot team's own
[evals](https://github.com/openemr/openemr/tree/master/agent/evals).
CATS measures **adversarial robustness specifically.** A
co-pilot that is highly accurate and highly exploitable is
worse than one that is moderately accurate and harder to
break.

### Not an attack tool

CATS is built to test systems the operating team owns. The
[trust-boundary controls](./ARCHITECTURE.md#31-trust-boundaries--run-authorization)
— Project allowlists, run-authorization requirements, the
two-layer output filter on adversarial content, audit-logged
campaign starts — exist to keep that boundary real. Running
CATS against systems the operator does not own is out of
scope and structurally discouraged by the platform.

---

## Workflow summary table

| Persona | Frequency | Primary surface | What CATS does for them that they cannot do by hand |
|---------|-----------|------------------|-------------------------------------------------------|
| AI / Security Engineer | Daily | CLI + dashboard | Read the Orchestrator's per-campaign plan + rationale and approve, edit, or reject before dispatch; generate attack variants at scale once dispatched; persist structured findings; run triple-gate regression replays after every release |
| Engineering Leadership / CISO | Weekly + release windows | Dashboard only | Show coverage trend release-over-release; pause critical findings for explicit approval; expose the audit trail |
| External Red-Team Contributor | Periodic | Git PRs + sandbox | Onboard new attack categories through a clean plugin contract; test in isolation before production use |

The pattern across all three personas is the same: **the humans
make judgment calls, the platform handles execution.** Where
that division of labor breaks down — where a human is making
mechanical decisions, or where the platform is making judgment
calls without a human review gate — is where CATS' design has
gone wrong. The
[architecture's trust boundaries](./ARCHITECTURE.md#31-trust-boundaries--run-authorization)
and the
[Judge's verification policy](./ARCHITECTURE.md#25-judge-integrity)
are the load-bearing answers to that question.
