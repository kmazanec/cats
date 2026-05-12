---
name: next-round
description: Pick up the next round from docs/ROADMAP.md, plan it, ask clarifying questions, build it on a worktree, self-review via a separate agent, then commit. Use when the user invokes /next-round, says "implement the next round", "build round N", "pick up round N", or asks to execute a milestone from the CATS implementation roadmap.
---

# CATS — Next Round

You are picking up an unimplemented round from
[`docs/ROADMAP.md`](../../../docs/ROADMAP.md) and shipping it
end-to-end: plan, clarify, build, self-review, commit. The
roadmap and the surrounding companion docs
([`ARCHITECTURE.md`](../../../ARCHITECTURE.md),
[`THREAT_MODEL.md`](../../../THREAT_MODEL.md),
[`USERS.md`](../../../USERS.md)) are the source of truth — the
round's planning-level fields (Goal, Outcome, Scope, DoD, Risks)
are locked at planning time and you do not edit them. You fill in
the round's Tasks, Decisions, and Retrospective sections as the
work happens.

If `$ARGUMENTS` contains a round number (e.g. `3`, `Round 3`,
`R3`), implement that round. Otherwise auto-detect the **lowest-
numbered round whose `Tasks` section still says "_to be filled
by Rn builder_"** — that's the next unimplemented round. If every
round in the file is started, stop and ask the user which to
work on.

## Hard rules

- **One round per invocation.** Do not roll over into the next
  round even if the chosen one finishes fast. The user
  re-invokes for the next.
- **Worktree, not master.** Multi-commit work runs in a sibling
  worktree on its own `feat/round-<n>-<slug>` branch. The user's
  CLAUDE.md memory mandates this for any work that touches more
  than a single file or produces more than one commit.
- **The roadmap's planning fields are locked.** Goal, Outcome,
  Scope (in/out), Definition of Done, Risks & Blockers were set
  during planning. If you believe one of these is wrong, surface
  it as a clarifying question — do not silently rewrite the
  planning frame.
- **Global DoD applies.** Per `docs/ROADMAP.md`'s "Definition of
  done — applies to every round" section: demoable, tested,
  evaluated where relevant, documented, audit-logged,
  type-clean, secrets-clean. No round ships without these.
- **Never push to master.** Per user memory: only the user
  pushes master. Local commits are fine; `git push` to any
  branch is not the skill's job unless the user explicitly asks.

## Phases

Execute these phases in order. Each phase has a hard
checkpoint — do not skip ahead.

### Phase 1 — Load the roadmap and select the round

1. Read [`docs/ROADMAP.md`](../../../docs/ROADMAP.md) end-to-end.
2. Resolve which round to work on:
   - If `$ARGUMENTS` names a round, use it.
   - Otherwise find the lowest-numbered round whose Tasks
     section is still empty (the placeholder
     `_to be filled by Rn builder_`).
3. Read the round's full content: Goal, Outcome, Scope (in /
   out), DoD, Risks & Blockers.
4. Read the **companion docs** for the architectural and
   threat-model context the round depends on:
   - [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) — at minimum
     the sections the round's Scope references
   - [`THREAT_MODEL.md`](../../../THREAT_MODEL.md) — if the
     round targets a category
5. Read **the previous round's Retrospective** (if any) — the
   builder of the prior round may have surfaced something that
   should change how this one is approached.
6. State (briefly, to the user) which round you've picked and
   one-sentence what it builds.

### Phase 2 — Clarify before planning

Before writing any plan, identify the genuinely ambiguous calls
in this round's Scope and DoD. **Use the AskUserQuestion tool**
to surface them. Ask only what's load-bearing — not every detail
that could conceivably be debated.

Good clarifying questions look like:

- "The round says the Output Filter is regex-only for R2; does
  that mean we skip the LLM-classifier scaffolding entirely, or
  build the interface and leave the implementation as a
  not-implemented stub for R(later)?"
- "The DoD says 'at least one Project successfully registered
  against the deployed co-pilot URL.' Is the deployed URL ready
  to register today, or do I need a placeholder?"

Bad clarifying questions look like:

- "Should we use FastAPI or Flask?" *(already decided in
  ARCHITECTURE.md §1.4)*
- "What model should the Judge use?" *(decided in §4.1)*

If the round is unambiguous, **skip this phase** and say so.
Don't manufacture questions for ceremony.

### Phase 3 — Plan in a TaskList

Once clarifying questions are resolved, write a TaskList
covering the round end-to-end. Use the project's task tooling
(`TaskCreate`). Each task should be a concrete deliverable —
not "implement the agent" but "write `cats/agents/orchestrator.py`
with the trivial-policy interface from R2 scope."

The plan must explicitly include tasks for:

1. Worktree creation and branch checkout
2. Implementation tasks per the Scope
3. Unit tests for new pure-function logic
4. Integration tests for new agent behavior using fake LLMs and
   the fake target Co-Pilot harness (Round 2+ — earlier rounds
   may not have agents yet)
5. **Eval suite additions** if the round touches Judge rubrics
   or fixtures (Round 3+)
6. Type-clean pass (`mypy --strict` + `ruff check`)
7. Documentation updates if any architectural decision changed
8. Filling in the round's `Tasks` and `Decisions` sections in
   `docs/ROADMAP.md` as work progresses
9. Self-review preparation (Phase 5 below)
10. Final commit(s)

Show the plan to the user before executing. Wait for the user
to either approve or redirect. Do not start implementation until
this gate clears.

### Phase 4 — Build

Execute the plan in a worktree:

```bash
git worktree add ../cats.worktrees/round-<n>-<slug> -b feat/round-<n>-<slug>
cd ../cats.worktrees/round-<n>-<slug>
```

Implement task by task. As you complete tasks, mark them done
in the TaskList **and** append to the round's `Tasks` section
in `docs/ROADMAP.md`. For each meaningful design call you make,
write a one-line entry in the round's `Decisions` section with
the rationale, not just the outcome.

Honor the architectural standards from
[`ARCHITECTURE.md`](../../../ARCHITECTURE.md):

- All LLM calls route through OpenRouter
- Family-diversity policy on Judge vs Red Team Tier-2
- Locked rubric versioning (`rubric/v1.md`, never edit in place)
- Trust boundaries: no Project becomes runnable without
  explicit allowlist; audit-log every campaign start
- OpenRouter account-level prompt logging stays OFF (CATS
  does its own)
- Two-layer output filter on adversarial content

Run tests early and often. Don't accumulate a 2-hour debugging
session at the end.

### Phase 5 — Self-review (via a separate agent)

**Do not review your own work directly.** Spawn a fresh agent
with `Agent({subagent_type: "general-purpose", ...})` using the
prompt below. The reviewing agent has no context from your
build phase — that's the point. It reads the diff cold and
judges whether the global DoD and the round's per-round DoD are
actually met.

The review prompt must include:

1. Which round was implemented (number + name)
2. The branch name and worktree path
3. The diff stat (output of `git diff --stat main...HEAD`)
4. The round's full DoD checklist from `docs/ROADMAP.md`
5. The global DoD from the top of `docs/ROADMAP.md`
6. Instruction: "Walk through each DoD item. For each, state
   PASS / FAIL / UNCLEAR with file:line evidence. Return a
   summary at the end: ship-ready, needs-fixes-then-ship, or
   reconsider-design. Keep total response under 800 words.
   Do not be polite — if a test is missing, say so."

When the review returns:

- **ship-ready** → proceed to Phase 6.
- **needs-fixes-then-ship** → address the review's specific
  items. After fixing, spawn **another** review agent (not the
  same agent), pass it the new diff plus the prior review's
  findings. Loop until the review says ship-ready or you've
  done two review rounds and remaining items are clearly
  out-of-scope for this round (in which case capture them as
  Round N+1 candidates in the Retrospective).
- **reconsider-design** → stop. Do not commit. Report the
  review's reasoning back to the user; they decide whether to
  rework the round, narrow its scope, or override.

### Phase 6 — Round retrospective

Before committing, fill in the round's `Retrospective` section
in `docs/ROADMAP.md`:

- **What went well** — specific, not generic ("LangGraph's
  PostgresSaver wired in 20 minutes" not "the round went
  smoothly")
- **What didn't** — specific. Friction, dead ends, surprises.
- **What to change for the next round** — concrete suggestions
  the next builder will read in Phase 1.

This is the only opinionated text the builder owns in the
roadmap doc. Make it useful for the next person — including
future-you.

### Phase 7 — Commit

Stage the changes. **Show the user the planned commit message
and the `git diff --stat` before committing.** Wait for the
user to confirm or redirect.

Commit message format:

```
feat(round-<n>): <one-line round name>

<one short paragraph summarizing what was built and why>

<bullet list of the meaningful changes>

Refs: docs/ROADMAP.md Round <n>
```

Include the `Assisted-by: Claude Code` trailer per the user's
git settings:

```bash
git commit --trailer "Assisted-by: Claude Code" -m "$(cat <<'EOF'
... message body ...
EOF
)"
```

If pre-commit hooks fail, fix the underlying issue and create a
**new** commit — do not amend. Do not use `--no-verify` unless
the user explicitly asks.

After the commit lands, do **not** push and do **not** merge
the worktree branch into main. Report:

- worktree path
- branch name
- commit SHA
- pointer to the round's Retrospective in `docs/ROADMAP.md`
- one sentence on what's ready for the user to verify

The user owns the merge and the push.

## What you do not do

- **Do not edit the round's planning fields** (Goal, Outcome,
  Scope, DoD, Risks). If one of those is wrong, surface it in
  Phase 2 as a clarifying question — but do not silently
  rewrite the planning frame.
- **Do not push to origin.** Local commits only.
- **Do not roll over into the next round** even if the current
  one finishes fast.
- **Do not skip the separate-agent review** even on a small
  round. The review is what makes "self-review" honest.
- **Do not write fixtures, prompts, or rubrics that lower the
  bar** to make the DoD pass. If a test is hard to write,
  surface it — don't fake it.

## Quick reference

| Phase | Action | Gate |
|-------|--------|------|
| 1 | Load roadmap + companion docs, pick round | State which round |
| 2 | Clarifying questions (via AskUserQuestion) | All ambiguities resolved |
| 3 | Plan as a TaskList | User approves plan |
| 4 | Build in worktree, update Tasks/Decisions live | All tasks done, tests pass |
| 5 | Spawn separate Agent for review | Review verdict = ship-ready |
| 6 | Fill in Retrospective | Retrospective is specific, not generic |
| 7 | Commit with trailer | User approves commit message; commit lands |
