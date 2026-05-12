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
only one technique is covered. From Round 3 onward, each round
is **tightly scoped to a single attack category or technique
from the threat model**, deepening coverage rather than adding
internal machinery.

This shape exists to avoid the classic agile failure mode of "we
built lots of infrastructure but nothing demoable." After Round 2,
CATS is the platform; everything that follows is the platform
getting better at its job. Each round is meant to be small
enough to ship cleanly and self-contained enough that the user
can see the value before the next round starts.

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

- [ ] _to be filled by R1 builder_

**Decisions.** *(builder records as made — preserve rationale, not just outcome)*

- _to be filled by R1 builder_

**Retrospective.** *(builder fills in after R1 ships)*

- What went well: _
- What didn't: _
- What to change for R2: _

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
  technique the user named, end of story
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

- [ ] _to be filled by R4 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R4 builder_

**Retrospective.** *(builder fills in after R4 ships)*

- What went well: _
- What didn't: _
- What to change for R5: _

---

## Round 5 — PHI / Cross-Patient Exfiltration

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

- [ ] _to be filled by R5 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R5 builder_

**Retrospective.** *(builder fills in after R5 ships)*

- What went well: _
- What didn't: _
- What to change for R6: _

---

## Round 6 — The platform decides what to test next

**Goal.** Stop making the user pick which attack category to run.
CATS becomes a platform that *learns*: it reads its own history,
notices what's been under-tested, what has open findings of what
severity, what's been quiet for too long, and chooses where to
spend the next attack on its own.

**Outcome.** A user can:

1. Start a campaign with just a target and a budget — no
   category — and the platform picks where to attack.
2. See a coverage view in the dashboard that shows, for every
   attack category, how much testing has happened, how recently,
   and what's currently open.
3. Watch the platform's category choices shift over a series of
   campaigns as findings land and coverage fills in — the
   under-tested categories rise, the saturated ones fall.
4. Set the platform's spending budget for a campaign and trust
   it to stop when the budget is exhausted, when nothing
   useful is being found, or when something is going badly
   wrong.

**Scope.**

In:
- Automatic category selection driven by the platform's
  observable state (coverage, severity of open findings,
  recency, plus a small dose of random exploration so nothing
  gets starved).
- A coverage view in the dashboard.
- Stop conditions: budget exhausted, no useful signal after a
  reasonable number of attempts, emergency halt when the judge
  is misbehaving.
- The platform's choice logic is deterministic and inspectable
  — a user can ask "why did it pick X next?" and get a
  legible answer.

Out:
- Using a separate LLM to re-tune the choice logic over time.
  This round proves the inspectable logic works; a smarter
  meta-layer can come later.

**Definition of done (in addition to global DoD).**

- [ ] Campaigns can be launched without specifying a category;
      the platform picks.
- [ ] Over a sequence of at least ten consecutive campaigns,
      the dashboard visibly shows priority shifting — and a
      user can read out why.
- [ ] Every stop condition triggers correctly when its
      condition holds; in particular, an obviously misbehaving
      judge halts the campaign rather than corrupting findings.

**Risks & blockers.**

- **Cold start.** With no history, the choice logic has to do
  something reasonable. Document the defaults; they will get
  pushed on.
- **Tuning by feel.** It will be tempting to tune the weights
  until the demo looks compelling. The discipline is to tune
  from real data, not from what makes the chart pretty.

**Tasks.** *(builder fills in as completed)*

- [ ] _to be filled by R6 builder_

**Decisions.** *(builder records as made)*

- _to be filled by R6 builder_

**Retrospective.** *(builder fills in after R6 ships)*

- What went well: _
- What didn't: _
- What to change for R7: _

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
