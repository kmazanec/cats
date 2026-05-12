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

CATS is built in **rounds**, each delivering a demonstrable
increment of working product. The first two rounds are larger by
necessity — Round 1 stands up the foundation; Round 2 brings every
agent into existence in its most basic form. From Round 3 onward,
each iteration is **tightly scoped to a single category or
technique** from the threat model — *adding scope to existing
agents, not building new ones.*

This shape exists to avoid the classic agile failure mode of "we
built lots of infrastructure but nothing demoable." After Round 2,
CATS is the platform; everything that follows is the platform
getting better at its job.

### Definition of done — applies to every round

Every round, regardless of scope, must satisfy these gates before
it is considered complete:

1. **Demoable.** The round's stated outcome is exercisable end-to-end
   against the live deployed co-pilot (or against the local docker
   target where the round explicitly says so).
2. **Tested.** Unit tests cover new pure-function logic.
   Integration tests cover new agent behavior using fake LLMs and
   the fake target Co-Pilot harness. Both run in CI on every commit.
3. **Evaluated** where relevant. If the round adds to the Judge's
   fixture set or category prompts, the eval suite runs against
   real LLMs (nightly CI job, not per-commit) and meets the
   per-category accuracy threshold.
4. **Documented.** The round's `Tasks`, `Decisions`, and
   `Retrospective` sections in this doc are filled in. Any
   architectural change is reflected back into
   [`../ARCHITECTURE.md`](../ARCHITECTURE.md) or
   [`../THREAT_MODEL.md`](../THREAT_MODEL.md) as appropriate.
5. **Audit-logged.** Every campaign run in this round is captured
   in the `audit_log` table per `ARCHITECTURE.md` §6.1, even in
   dev.
6. **Type-clean.** `mypy --strict` passes; `ruff check` passes.
7. **Secrets-clean.** No real credentials in the repo, in
   commits, or in test fixtures.

### Cross-cutting workstreams

Some work is not a milestone — it threads through every round and
needs continuous attention rather than a single ship date.

- **CI/CD.** GitLab jobs running ruff + mypy
  + pytest on every push from Round 1 forward. Nightly job
  running real-LLM evals from Round 3 forward.
- **Security hygiene.** OpenRouter keys per-env, spend caps, no
  `Authorization` header logging, `.env` in `.gitignore`,
  pre-commit hook for secrets scanning. Continuous from Round 1.
- **Observability.** LangSmith tracing on every LLM call from
  Round 2 forward. Postgres-backed coverage and cost rollups
  from Round 2 forward. Dashboard panels added per round as the
  data appears.
- **Threat-model sync.** When a round teaches us something about
  the target (new attack surface, a defense that holds or
  doesn't), update [`../THREAT_MODEL.md`](../THREAT_MODEL.md) §6
  verification results.

### Out of scope for this roadmap

These are deliberate post-roadmap items. Surfacing them here
prevents scope creep into earlier rounds.

- White-hat mode (per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §7).
  Data model is forward-compatible from Round 1 (`mode` and
  `exploitability` columns); implementation is post-roadmap.
- Multi-tenant deployments (different teams sharing one CATS
  instance with isolated Project sets).
- Dashboard polish beyond the operator-functional minimum —
  charts, heatmaps, custom views.
- Cross-Judge ensemble voting (decision deferred until single-Judge
  drift is empirically observed).
- BYOK direct routing for cost optimization at 100K-run scale.
- Self-hosted inference workers.

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

**Goal.** Stand up the rails for everything else: a CATS service
that knows about Projects and can talk to OpenRouter and LangSmith,
behind authentication and audit logging, with no agents yet.

**Outcome.** An engineer can:

1. `cats project add <name> --base-url=...` register a target
2. `cats project list` see registered Projects
3. Open the dashboard at `localhost:8080` and see the Projects list
4. Authenticate (basic role-gated auth) and verify the audit log
   captured the login
5. Run `cats health` and see a green OpenRouter check, green
   LangSmith check, green Postgres check, green Redis check

**Scope.**

In:
- Python service skeleton (FastAPI, alembic, pydantic, async
  SQLAlchemy or psycopg, redis-py)
- Postgres schema: `projects`, `audit_log`, `campaigns` (empty
  table, schema only), `users` for auth, with `mode` and
  `exploitability` columns on `findings` reserved for the
  white-hat track even though the table is otherwise empty
- Project CRUD via CLI and REST (`POST /projects`,
  `GET /projects`, `PATCH /projects/<id>`, `DELETE /projects/<id>`)
- Project `allow_run_against` flag (defaults to false)
- Four-role RBAC (`viewer`, `operator`, `senior_operator`, `admin`)
- OpenRouter client wrapper with per-env key from env vars + spend
  cap + family-diversity policy as data (not enforced yet — just
  the config schema)
- LangSmith client wrapper with project name from env
- Dashboard skeleton: HTMX-served `/`, `/projects`, `/audit`, all
  read-only views
- Audit log table + middleware that writes every authenticated
  request to it
- `cats health` CLI command exercising all external dependencies

Out:
- Any agent (Round 2)
- Any campaign-start endpoint (Round 2)
- Any Findings UI (Round 3+)
- Any dashboard styling beyond functional minimum

**Definition of done (in addition to global DoD).**

- [ ] Local docker-compose brings up Postgres + Redis + the CATS
      service with one command
- [ ] All four global health checks green
- [ ] Project CRUD round-trip tested end-to-end via integration
      test
- [ ] Audit log row exists for every CRUD action in the test
- [ ] Dashboard accessible via browser, all three pages render
      with seeded data
- [ ] Pre-commit hook installed and verified to catch a planted
      secret
- [ ] CI pipeline running on every push: ruff, mypy --strict,
      pytest (unit + integration)
- [ ] README updated with quickstart commands
- [ ] At least one Project successfully registered against the
      deployed co-pilot URL (live target)

**Risks & blockers.**

- **OpenRouter keys.** Need a development account with budget
  before any LLM-touching round. Resolve at start of R1.
- **LangSmith project setup.** Project name must match co-pilot's
  org per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §3.4. Verify
  early.
- **Postgres on the droplet.** Confirm capacity / port / managed
  vs self-hosted before R1 deploy.
- **Auth scope creep.** RBAC is easy to over-engineer. Aim for
  the cheapest correct implementation (e.g. four-row roles table,
  middleware decorator); resist building a full identity system.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R1 builder_

**Decisions.** *(builder records as made — preserve rationale, not just outcome)*

- _to be filled by R1 builder_

**Retrospective.** *(builder fills in after R1 ships)*

- What went well: _
- What didn't: _
- What to change for R2: _

---

## Round 2 — All seven agents end-to-end on one technique

**Goal.** Every agent role from
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.1 exists in its most
basic form, wired through the LangGraph state machine, end-to-end
against the live target. The platform becomes the platform.

**Outcome.** An engineer can:

1. `cats campaign run --project=<id> --category=prompt-injection-direct`
2. Watch the dashboard's `/campaigns/<id>` page show the
   Orchestrator's plan, then the Injection specialist's attack,
   then the Output Filter's verdict, then the Judge's verdict,
   then a Finding row appearing in `/findings`
3. Click into the Finding to see the attack, response, Judge
   verdict, and LangSmith trace deep-link
4. See cost / token usage per agent in the dashboard

**Scope.**

In:
- All seven agent nodes implemented in their basic shape:
  - **Orchestrator** — for R2, a *trivial* policy: "run the
    category specified in the campaign config, one attack, then
    halt." Bandit policy is post-R2.
  - **Red Team Router** — dispatches to the single Injection
    specialist; other specialists return `not implemented` for now.
  - **Injection Specialist** — one hard-coded attack from the
    threat-research corpus (e.g. Policy Puppetry against the
    co-pilot's chat endpoint). System prompt + zero-shot Hermes 4
    call.
  - **Mutator** — for R2, identity-only (returns the attack
    unchanged). Real mutation is Round 3+.
  - **Output Filter** — regex layer only (LLM classifier deferred
    to a later round). Strips zero-width, NFKC-normalizes,
    quarantines obvious PII patterns.
  - **Judge** — deterministic-only for R2. For Policy Puppetry the
    success condition is "did the response contain the planted
    instruction's payload?" — string-match check, no LLM rubric.
  - **Documentation Agent** — Claude Sonnet 4.6 writes a
    structured `vulnerability_reports` row. No critical-severity
    human gate yet (every Finding is severity `medium` in R2).
- Postgres tables filled out: `campaigns`, `attack_events`,
  `findings`, `vulnerability_reports` (with the `mode` and
  `exploitability` columns set to defaults)
- LangGraph state machine wiring with checkpointing
- LangSmith tracing on every LLM call
- Dashboard pages: `/campaigns/<id>` (live SSE-fed), `/findings`,
  `/findings/<id>`
- `cats campaign run` CLI
- Per-agent cost tracking in `attack_events`

Out:
- Real Orchestrator bandit (Round 4 or later)
- Real Mutator (Round 4 or later)
- LLM-classifier output filter (later)
- Critical-severity human gate (later)
- Multiple specialists working (Round 3 brings Exfil; Round 4
  ToolAbuse; etc.)
- Regression harness / triple gate (Round N where it matters)

**Definition of done (in addition to global DoD).**

- [ ] A campaign starts via CLI and produces exactly one Finding
      row against the live deployed co-pilot
- [ ] Every LangGraph node transition is checkpointed and
      resumable (kill the process mid-campaign, restart, finish)
- [ ] Every LLM call has a LangSmith trace; the Finding row
      carries the trace ID
- [ ] Integration test: full pipeline against a fake target Co-Pilot
      with a fake LLM, deterministic and runs under 5 seconds
- [ ] Integration test for each agent node in isolation against
      a stubbed upstream
- [ ] Cost per agent is non-zero and reasonable in
      `attack_events` rows
- [ ] Output filter integration test: a payload containing a
      planted PII pattern is quarantined and does not reach the
      target

**Risks & blockers.**

- **Hermes 4 availability on OpenRouter.** Validate model ID and
  pricing at start of R2; if availability is flaky, swap fallback
  order in the model assignment table.
- **LangGraph checkpointer version.** Pin per
  [`../THREAT_MODEL.md`](../THREAT_MODEL.md) §6.1 audit (Postgres
  checkpointer; no SQLite). Verify before R2 begins.
- **Fake target Co-Pilot harness.** Need this for fast integration
  tests; building it well is itself a small project. Budget time.
- **LangSmith trace volume.** Free tier may not cover R2 + nightly
  evals. Verify plan/billing before R2.
- **The "hard-coded attack" temptation.** Round 2's Injection
  specialist runs one zero-shot attack. Resist the urge to add
  variants here — that is Round 3's job. Keep R2 boring on the
  attack-craft side so all the energy goes into wiring.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R2 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R2 builder_

**Retrospective.** *(builder fills in after R2 ships)*

- What went well: _
- What didn't: _
- What to change for R3: _

---

## Round 3 — Prompt Injection, in depth

**Goal.** Take the rank-1 category from
[`../THREAT_MODEL.md`](../THREAT_MODEL.md) §2.1 (L×I = 25) and
make it real — the Injection specialist now exercises the full
technique table, the Mutator actually mutates, the Judge handles
behavioral cases via the LLM rubric, and the Finding output is
publishable.

**Outcome.** An engineer can:

1. Run a campaign with `--category=prompt-injection` and have the
   Injection specialist try multiple techniques (Policy Puppetry,
   Many-Shot Jailbreaking, Crescendo single-shot, encoded
   payloads, SPE-LLM extraction probes)
2. See the Mutator producing variants of partial-successes
3. See the Judge using deterministic-first then LLM rubric, with
   the rubric version recorded on every verdict
4. Open a Finding and see it labeled with its MITRE ATLAS
   technique ID and OWASP LLM Top 10 ID
5. Run the nightly eval CI job and see Injection-category Judge
   accuracy reported against the ground-truth fixture set

**Scope.**

In:
- Injection specialist prompt expanded to cover the
  [`./W3_THREAT_RESEARCH.md`](./W3_THREAT_RESEARCH.md) §1.1, §1.3,
  §1.6, §1.8 technique table — direct injection only for this
  round (docx indirect is Round 4)
- Mutator implementation: real Mutator on DeepSeek V3.2 producing
  N variants of a partial-success
- Judge rubric v1 for `prompt-injection-direct` category, locked
  and versioned in `cats/categories/prompt-injection-direct/rubric/v1.md`
- Ground-truth fixture set: 30-50 hand-labeled
  `(attack, response, expected_verdict)` triples seeded from
  LLMail-Inject + hand-authored against co-pilot specifics
- Per-category deterministic post-condition implementations
  (canary string match, SPE locked-prompt extraction detector,
  emitted-URL pattern check)
- Nightly CI eval job running real-LLM Judge against fixtures;
  fails the build if accuracy drops below 95% on Injection
- Findings carry `atlas_technique_id` and `owasp_llm_id` columns
- Documentation Agent produces a real vulnerability report (the
  brief requires ≥3 by Final; this round delivers the first one)

Out:
- Indirect injection via uploaded docx (Round 4 — different
  pipeline, deserves its own round)
- Real Orchestrator bandit (Round 6 or later — Round 3 still
  uses the trivial "run this category" policy from R2)
- Other categories (Exfil = Round 5, etc.)

**Definition of done (in addition to global DoD).**

- [ ] Injection specialist's system prompt covers all five
      direct-injection sub-techniques from §1.1, §1.3, §1.6, §1.8
- [ ] Mutator produces N ≥ 3 variants per partial-success and
      these are visible in `attack_events`
- [ ] Locked rubric v1 lives at the per-category path; CI
      forbids modifying v1 (must bump to v2 instead)
- [ ] Judge fixture set has at least 30 entries; nightly eval
      passes with accuracy ≥ 95%
- [ ] One vulnerability report exists at
      `reports/<finding-id>.md` produced by the Documentation
      Agent and reviewed by a human
- [ ] Finding rows carry both ATLAS and OWASP IDs

**Risks & blockers.**

- **Fixture labeling bias.** Hand-labeling 30-50 triples is real
  hand-work and the labels can reflect the labeler's blind spots.
  Mitigation: have a second reviewer spot-check 20% of labels.
- **Judge LLM cost on nightly eval.** 30-50 fixtures × Haiku 4.5
  is small per run but adds up. Cap nightly spend explicitly.
- **Rubric drift across LLM versions.** If OpenRouter routes us
  to a different Haiku build than yesterday, accuracy can shift.
  Pin via OpenRouter's provider config; alert on drift.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R3 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R3 builder_

**Retrospective.** *(builder fills in after R3 ships)*

- What went well: _
- What didn't: _
- What to change for R4: _

---

## Round 4 — Indirect injection via `.docx`

**Goal.** Reach the highest-impact attack surface identified in
[`../THREAT_MODEL.md`](../THREAT_MODEL.md): indirect injection via
uploaded `.docx` referral letters (the EchoLeak / ForcedLeak
shape). This round teaches the platform to *upload* attacks, not
just send them in chat.

**Outcome.** An engineer can:

1. Run a campaign with `--category=prompt-injection-indirect-docx`
   and watch the Injection specialist generate adversarial docx
   payloads
2. See the Output Filter accept them (they're attack payloads, not
   dangerous PII)
3. See the campaign upload them to the live co-pilot via the docx
   ingestion endpoint
4. See the Judge verify whether the planted instruction reached
   the model's behavior (via canary token leak or behavioral
   tell)
5. See findings labeled with the specific docx technique that
   succeeded (white-text / zero-width / homoglyph / etc.)

**Scope.**

In:
- Docx generation pipeline: the Injection specialist emits
  *structured docx attack specs* (which technique, where to
  plant the payload, what the canary string is) and a
  deterministic builder turns the spec into a real `.docx` ZIP
- Per-technique builders for white-color text, tiny-font,
  off-page positioning, zero-width smuggling, homoglyph
  substitution, tracked-changes, header/footer hiding,
  field-code injection
- Upload-to-target pipeline: hits the co-pilot's actual docx
  upload endpoint with the generated `.docx`
- Judge deterministic check: did the canary string appear in
  the assistant's response? Did the assistant follow the
  planted instruction?
- Fixture set expanded with docx-specific labeled triples
- Findings tagged with the specific technique that succeeded

Out:
- Extraction Poisoning → `accept_fact` simulation (the
  end-to-end "clinician clicks Accept" path is its own round)
- PHI Exfiltration (Round 5)

**Definition of done (in addition to global DoD).**

- [ ] At least six docx techniques implemented as structured
      builders, each round-trip tested via unit test
- [ ] One end-to-end test against the live deployed co-pilot
      demonstrating an actual successful injection (or a clear
      negative result if the co-pilot's defenses hold — both
      are valuable)
- [ ] Judge fixture set extended; accuracy holds ≥ 95% on the
      indirect category
- [ ] A vulnerability report on the most impactful docx finding
      lands in `reports/`
- [ ] If any docx defense in the co-pilot was breached, the
      finding is reflected back into
      [`../THREAT_MODEL.md`](../THREAT_MODEL.md) §6.2 (verified
      gap)

**Risks & blockers.**

- **Live target acceptance.** The deployed co-pilot may rate-limit
  or reject docx uploads from the CATS service IP. Verify early.
- **Docx structural correctness.** Adversarial docx is still
  *valid* docx — file must open in Word, Pages, and Google Docs
  without warnings. The technique payloads have to be invisible
  to humans AND survive validation. Test in real Word / Pages /
  Drive.
- **Canary token detection in noisy responses.** Some attacks
  succeed but the response paraphrases the canary; the canary
  doesn't string-match. Need careful canary design (rare token
  sequences) or a Judge fallback to LLM-rubric.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R4 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R4 builder_

**Retrospective.** *(builder fills in after R4 ships)*

- What went well: _
- What didn't: _
- What to change for R5: _

---

## Round 5 — PHI / Cross-Patient Exfiltration

**Goal.** Activate the Exfil specialist (currently a stub from R2)
against the rank-3 category in [`../THREAT_MODEL.md`](../THREAT_MODEL.md)
(L×I = 15 after the audit). Verify the markdown-image-renderer
defense in the co-pilot is as solid as the verification pass
claims (§6.2 of the threat model). Surface what does still work
— tool-parameter exfil, steganographic SSE, citation-payload
side channels.

**Outcome.** An engineer can:

1. Run a campaign with `--category=phi-exfil` and watch the Exfil
   specialist generate exfil-shaped attacks (canary-token
   planted patient data, markdown-image probes, tool-parameter
   stuffing)
2. See the Judge verify exfil success via the deterministic
   canary-token check
3. See findings clearly distinguishing which exfil channel
   succeeded (or, ideally, that none did because the co-pilot's
   defenses hold)

**Scope.**

In:
- Exfil specialist prompt and few-shots covering
  [`./W3_THREAT_RESEARCH.md`](./W3_THREAT_RESEARCH.md) §2.1,
  §2.3, §2.4, §2.5, §2.7
- Canary token planting protocol: synthetic patient charts in
  the local docker target with unique tokens; the deployed prod
  target gets a per-campaign canary in a dedicated test chart
- Judge deterministic checks: token-presence in response,
  token-presence in any tool-call parameter, audit-log scan for
  unusual tool-param sizes
- Judge rubric for behavioral exfil cases (model emitted a
  markdown-image URL containing exfil-shaped data even if the
  client wouldn't render it)
- Fixture set for the Exfil category
- Cross-patient probing tests: can a campaign authed as
  Clinician-A get Patient-B's data?

Out:
- Citation Fabrication (Round 6 — different shape, different
  techniques)
- Extraction Poisoning (Round 8 — needs the docx pipeline + a
  simulated Accept-click model)

**Definition of done (in addition to global DoD).**

- [ ] Exfil specialist generates at least four distinct
      exfil-shaped attacks per campaign
- [ ] Canary-token plant and detect pipeline works end-to-end
      in the local target
- [ ] Cross-patient probe test exists and passes (or fails with
      a real finding)
- [ ] Judge accuracy on Exfil fixtures ≥ 90% (lower threshold
      than Injection because signal is fuzzier per the threat
      model)
- [ ] One Exfil vulnerability report (or "no exploitable exfil
      found in this run" report — both are publishable)

**Risks & blockers.**

- **PHI handling in the local target.** Use synthetic data only.
  Triple-check no real PHI leaks into commits, logs, or
  LangSmith traces.
- **Canary token uniqueness vs detection.** Tokens must be
  unique-enough to false-positive at near-zero, but pattern-able
  enough that the Judge can scan for them. Design carefully.
- **The "no findings" outcome.** R5 might confirm the threat
  model is right (the markdown-image renderer blocks the easy
  path). That's a valuable finding and the report should treat
  it as one — not a failure.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R5 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R5 builder_

**Retrospective.** *(builder fills in after R5 ships)*

- What went well: _
- What didn't: _
- What to change for R6: _

---

## Round 6 — Orchestrator bandit policy + coverage matrix

**Goal.** Replace R2's trivial "run the category specified"
policy with the real epsilon-greedy bandit from
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2.4. CATS becomes a
*platform that learns* — the next attack is chosen from
observability state, not from a CLI flag.

**Outcome.** An engineer can:

1. Run `cats campaign run --project=<id> --budget=$5` *without
   specifying a category*
2. Watch the Orchestrator pick the next category based on
   coverage gaps × severity weights × recency decay
3. See the dashboard's `/coverage` page showing the matrix and
   the bandit's weighting
4. Observe over multiple campaigns that the bandit re-prioritizes
   categories as findings land and coverage fills in

**Scope.**

In:
- Deterministic epsilon-greedy bandit implementation, pure Python
- Coverage matrix view in dashboard
- Bandit weighting parameters (coverage gap, severity, recency,
  epsilon) configurable per environment
- Halt conditions: budget exhausted, no signal (N consecutive
  fails), emergency stop on Judge errors
- Unit tests for bandit math (no LLMs involved)

Out:
- Meta-loop LLM weight tuning (later round — first verify the
  deterministic bandit works on its own)

**Definition of done (in addition to global DoD).**

- [ ] Bandit unit-tested with seeded RNG: identical input state
      → identical category choice
- [ ] Coverage matrix updates after every campaign
- [ ] Halt conditions trigger correctly under each condition
- [ ] Over a 10-campaign sequence, the bandit visibly
      re-prioritizes (verified in a dashboard screenshot or a
      reproducible script)

**Risks & blockers.**

- **Cold-start.** With zero history, the bandit needs reasonable
  defaults. Document them.
- **Weight tuning by feel.** Resist the urge to over-tune weights
  to make the demo look good. Tune from data, not vibes.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R6 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R6 builder_

**Retrospective.** *(builder fills in after R6 ships)*

- What went well: _
- What didn't: _
- What to change for R7: _

---

## Round 7 — Tool Misuse specialist

**Goal.** Activate the ToolAbuse specialist (stubbed in R2)
against the rank-5 category (L×I = 16). Surface the over-fetch
amplifier story from [`../THREAT_MODEL.md`](../THREAT_MODEL.md)
§2.3 — even with no chat-callable write tool, the supervisor can
be coerced into reading more chart data than the briefing
warrants, amplifying any later exfil.

**Outcome.** An engineer can:

1. Run a campaign with `--category=tool-misuse` and watch the
   ToolAbuse specialist generate forced-tool-invocation attacks
2. See the Judge verify success via tool-call audit-log scan
   against a "legitimate-need set" per briefing type
3. See findings clearly tagged with the misused tool and the
   over-fetched data classes

**Scope.**

In:
- ToolAbuse specialist prompt covering
  [`./W3_THREAT_RESEARCH.md`](./W3_THREAT_RESEARCH.md) §3.1, §3.2,
  §3.3, §3.4, §3.5
- Audit-log scan post-condition implementation: given a campaign,
  pull the co-pilot's tool-call audit log and compare against the
  campaign's "legitimate-need set" for that briefing type
- Parameter-pollution test corpus (Zod-schema-violation attempts)
- Fixture set for ToolAbuse category
- "Legitimate-need set" data structure per briefing type
  documented in `cats/categories/tool-misuse/legitimate-need.yaml`

Out:
- Confused-deputy via prior chart content (separate sub-technique,
  later round)
- Clawdrain-style cost amplification (DoS lives in its own round)

**Definition of done (in addition to global DoD).**

- [ ] ToolAbuse specialist generates at least three distinct
      forced-over-fetch attacks per campaign
- [ ] Audit-log scan compares actual tool calls against the
      legitimate-need set; mismatches become findings
- [ ] Parameter-pollution test corpus exists; the Judge classifies
      each correctly
- [ ] Judge accuracy on ToolAbuse fixtures ≥ 90%
- [ ] One ToolAbuse vulnerability report (or "scope is correctly
      enforced" report)

**Risks & blockers.**

- **Access to the co-pilot's tool-call audit log.** Verify CATS
  can read it (read-only) before this round begins. May require
  an OpenEMR-side change.
- **Defining "legitimate need" objectively.** This is subjective
  per briefing. Document the rationale in the category's
  legitimate-need.yaml so the labeler's reasoning is auditable.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R7 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R7 builder_

**Retrospective.** *(builder fills in after R7 ships)*

- What went well: _
- What didn't: _
- What to change for R8: _

---

## Round 8 — Regression harness and triple-gate

**Goal.** Implement the regression-suite triple gate from
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §6.4. Once findings
exist (from R3-R7), the platform needs to verify whether fixes
actually held. Without this, every CATS run is a one-shot.

**Outcome.** An engineer can:

1. Confirm a finding from R3-R7 in the dashboard
2. After the co-pilot team ships a fix, click "Re-run regression"
3. Watch the regression harness re-fire the attack against the
   redeployed target
4. See the triple gate evaluate: deterministic post-condition
   passes? Judge against the locked rubric version returns
   `fail`? Behavioral fingerprint matches a captured refusal
   exemplar?
5. See the finding marked `fixed` only if all three gates pass;
   otherwise escalated for human review

**Scope.**

In:
- Behavioral-fingerprint implementation: capture refusal exemplar
  on first verified fix; embedding-distance check at regression
  time using a small sentence-transformers model
- Triple-gate orchestration: a dedicated graph branch that runs
  all three checks and surfaces results
- Dashboard regression panel
- Deployment-triggered campaign mode: GitLab CI webhook receiver
  that fires regression suite on co-pilot redeploy
- Locked-rubric versioning enforcement: the regression uses the
  rubric version that produced the original finding, even if the
  current rubric has been bumped

Out:
- Critical-severity human approval gate (next round)

**Definition of done (in addition to global DoD).**

- [ ] Re-run regression on a known finding produces a verdict
      with all three gates explicitly recorded
- [ ] A regression with a "refused differently" pattern (fails
      gate 3 but passes gates 1-2) is flagged for human review,
      not auto-marked fixed
- [ ] Deployment webhook tested end-to-end: simulate co-pilot
      redeploy, watch CATS auto-fire the regression suite
- [ ] Sentence-transformers model dependency is pinned and
      cached locally (don't re-download per CI run)

**Risks & blockers.**

- **Refusal exemplar staleness.** If the co-pilot's prompt
  changes substantially, the captured exemplar may stop matching
  even valid refusals. Need a strategy for re-capturing.
- **Embedding model drift.** Sentence-transformers releases new
  models; pin a specific revision.
- **GitLab CI webhook security.** Verify HMAC signatures; don't
  accept arbitrary POSTs.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R8 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R8 builder_

**Retrospective.** *(builder fills in after R8 ships)*

- What went well: _
- What didn't: _
- What to change for R9: _

---

## Round 9 — Critical-severity human approval gate

**Goal.** Implement the trust boundary from
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) §6.1 and
[`../THREAT_MODEL.md`](../THREAT_MODEL.md) §0 — when the
Documentation Agent is about to mark a finding `critical`, it
pauses and waits for an explicit `senior_operator` approval
before the finding becomes a tracked, remediation-bound row.

**Outcome.** An engineer with `senior_operator` role can:

1. See the dashboard's `/approval-queue` page showing pending
   critical-severity findings
2. Drill into a pending finding, see the attack, response,
   Judge verdict, and proposed report
3. Approve or reject; approval is recorded against the finding's
   trace ID in the audit log
4. Watch the finding become `confirmed-and-tracked` only after
   approval; an `operator` (not senior) attempting the same
   action gets `403 Forbidden`

**Scope.**

In:
- Documentation Agent's pause-on-critical behavior using a
  LangGraph interrupt
- Approval queue API + dashboard page
- RBAC enforcement on `POST /findings/<id>/approve` (only
  `senior_operator` and `admin`)
- Notification dispatch (Slack webhook or email — pick whichever
  the team uses) when a critical finding lands in the queue
- Audit-log entry per approval/rejection with the approver, the
  trace ID, and the rationale (text field, required)

Out:
- Cross-Judge ensemble voting (deferred indefinitely per the
  out-of-scope list)

**Definition of done (in addition to global DoD).**

- [ ] LangGraph interrupt-and-resume works end-to-end; a campaign
      that produces a critical finding pauses, waits for approval,
      then resumes
- [ ] Forbidden role attempting approval gets 403; allowed role
      gets through
- [ ] Notification dispatch verified in dev (Slack test channel)
- [ ] Audit log shows approval rationale text

**Risks & blockers.**

- **LangGraph interrupt semantics.** Verify that interrupting and
  resuming preserves state correctly across process restarts.
  This is what checkpointing is for, but test it.
- **Approval queue growing unboundedly.** Findings should
  auto-stale after N days with no approval — define N (e.g. 14
  days). After staling, they become "investigation needed"
  rather than `confirmed-and-tracked`.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R9 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R9 builder_

**Retrospective.** *(builder fills in after R9 ships)*

- What went well: _
- What didn't: _
- What to change for R10: _

---

## Round 10 — Multi-turn / Crescendo

**Goal.** Add multi-turn campaign support so the platform can
run Crescendo-style attacks (rank-7 category, L×I = 16). Up to
this point every campaign has been single-turn; this round
extends the LangGraph state machine and the Mutator to handle
multi-turn attack sequences.

**Outcome.** An engineer can:

1. Run a campaign with `--category=multi-turn-crescendo` and
   watch a multi-turn dialogue unfold (each turn benign in
   isolation, cumulative effect crossing a safeguard)
2. See the Judge evaluate the *final* turn against the rubric
   while having access to the full conversation history
3. See findings labeled with the turn-count required to break
   through

**Scope.**

In:
- Multi-turn CampaignState extensions (turn history, per-turn
  agent state)
- Crescendo specialist (a variant of the Injection specialist
  with a multi-turn system prompt)
- Mutator extension: mutate by *adding a next turn* rather than
  rewriting the existing attack
- Judge rubric covering multi-turn success conditions
- Fixture set with multi-turn triples (each entry is now a
  sequence, not a single attack)

Out:
- MINJA-shape persistent memory poisoning (later — needs a
  different threat model: cross-session state surviving
  conversation reset)

**Definition of done (in addition to global DoD).**

- [ ] A multi-turn campaign with at least 5 turns runs end-to-end
- [ ] The Judge receives the full turn history and produces a
      verdict that references which turn the attack succeeded on
- [ ] Per-turn cost is tracked separately in `attack_events`
- [ ] Multi-turn fixtures have at least 15 entries

**Risks & blockers.**

- **Per-conversation cost explosion.** Multi-turn attacks
  multiply token usage. Per-campaign budget caps need to be
  enforced more tightly.
- **State serialization growing.** LangGraph state for a 10-turn
  conversation can be large; verify checkpointer handles it.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R10 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R10 builder_

**Retrospective.** *(builder fills in after R10 ships)*

- What went well: _
- What didn't: _
- What to change for R11: _

---

## Round 11 — Clinical Misinformation Propagation

**Goal.** Reach the rank-2 category by L×I (= 25): a
healthcare-specific threat that's tied with Prompt Injection for
top-priority. The Nature Comm Med 2025 vignette set is the seed
corpus.

**Outcome.** An engineer can:

1. Run a campaign with `--category=clinical-misinformation` and
   watch the platform inject a deliberately false clinical
   premise into a briefing question
2. See the Judge evaluate whether the co-pilot's response
   propagated the false premise verbatim or as established
   context
3. See findings tied to specific Nature Comm Med vignette IDs
   for reproducibility

**Scope.**

In:
- Clinical Misinformation specialist (decision at build time:
  reuse Injection specialist with a category prompt, or new
  fourth specialist file — pick based on R3-R5 learnings)
- Nature Comm Med 2025 vignette corpus imported as fixtures
- Judge deterministic check: did the planted false value appear
  verbatim in the response?
- Judge rubric for premise propagation (LLM rubric for the
  fuzzy case where the model paraphrases the false premise)

Out:
- Cross-Judge ensemble voting (still deferred)

**Definition of done (in addition to global DoD).**

- [ ] Nature Comm Med vignette corpus is in the fixture set
      (or a representative subset of 50+ vignettes)
- [ ] Clinical Misinformation specialist runs end-to-end against
      the live target
- [ ] Judge accuracy on this category ≥ 85% (lower threshold
      because the harm is fuzzier than direct injection)
- [ ] At least one finding documented as a clinical-safety risk
      (or a "premise propagation correctly resisted" finding)

**Risks & blockers.**

- **Fixture licensing.** Verify the Nature Comm Med 2025 corpus
  can be redistributed in the fixture set, or if we need to
  cite-and-derive rather than copy.
- **The "did it propagate" call is genuinely hard.** Even a
  human medical reviewer can disagree on whether a response
  "anchored" on the false premise. Expect lower Judge accuracy
  here and resist the urge to tune fixtures to make accuracy
  look better.

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
*depth, not breadth*:

- **Extraction Poisoning → `accept_fact`** (L×I = 20, the
  highest-stakes write path). Needs a simulated-clinician-Accept
  model — a new agent-shape, deserves its own round.
- **Citation & Evidence Fabrication** (L×I = 20). Bbox pipeline
  awareness; closer to depth in the Exfil specialist's territory
  than its own round.
- **Identity & Role** (L×I = 6 after audit). Low priority;
  scheduled when other categories are stable.
- **DoS / Cost Amplification** (L×I = 12). Deterministic-only,
  no LLM Red Team needed; cheap to add when prioritized.
- **Output Filter LLM classifier** (deferred from R2's regex-only
  layer). Cheap small model for the second-layer scan.
- **Cost-analysis publishing**. The brief's required AI Cost
  Analysis deliverable (100 / 1K / 10K / 100K runs); pull from
  real telemetry once enough campaigns have run.
- **White-hat mode**. Per
  [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §7. Listed as
  post-roadmap above.

The roadmap stays open-ended past Round 11 deliberately — what
to build next is a function of what the platform finds and where
the co-pilot evolves.
