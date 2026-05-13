> **Target:** `agent/src/graph/nodes/supervisor.ts`, `agent/src/server/enrichPendingUploads.ts`
> **Surface:** Conversational-briefing graph — supervisor handoff loop on a turn whose envelope carried chart-enriched `pendingUploads`.
> **Severity:** Medium — denial-of-service on a single conversation. Any patient with several un-extracted Clinical-Copilot-categorized chart documents could not get a briefing at all (LangGraph recursion limit hit, no assistant message returned). No PHI exposure, no auth bypass; the next turn could still succeed if the documents got extracted out-of-band.
> **Status:** Fixed in openemr commit 2ff40efba
> **Found:** 2026-05-13 — CATS campaign [`10f44930-413c-4ba0-805e-81e3195af83a`](http://localhost:8400/campaigns/10f44930-413c-4ba0-805e-81e3195af83a); failing LangSmith trace [`019e226c-6e7b-75ec-a32e-0951b5317eba`](https://smith.langchain.com/o/6f33ee54-02bc-45ae-a01f-aa117988c05f/projects/p/929302e5-8694-4e08-9756-ea7b5e5ff720?peek=20260513T173952Z019e226c-6e7b-75ec-a32e-0951b5317eba) in `openemr-clinical-copilot-dev`.
> **Reported:** 2026-05-13 (in-thread report to the OpenEMR maintainer; no external issue/PR opened).
> **Fixed:** 2026-05-13 — openemr commit `2ff40efba` ("fix(agent): cap chart-enriched pendingUploads to prevent supervisor cap-hit").
> **Class:** DoS — agent graph recursion (per-turn handoff fanout exhausts LangGraph `recursionLimit`).

## What broke

A briefing request for a patient with several un-extracted
Clinical-Copilot-categorized documents on the chart never returned an
assistant message. The trace shows ten consecutive `kickoffExtraction`
nodes (one per un-extracted doc) plus eleven `supervisor` calls, after
which LangGraph's default `recursionLimit` of 25 fired and the turn
ended with no `synthesize`, no `verify`, no `format` — the panel saw
the spinner stall and the briefing never rendered. The user-visible
effect: clinicians whose charts had any backlog of legacy-Documents-UI
uploads couldn't get a briefing at all.

## Root cause (OpenEMR side)

Two layers cooperated to produce the fanout:

1. `agent/src/server/enrichPendingUploads.ts` discovers every
   Clinical-Copilot-categorized chart document that doesn't yet have
   an `extraction_artifacts` row and splices the lot into
   `RequestEnvelope.pendingUploads` indiscriminately — chat-panel
   uploads and chart-side uploads were structurally identical.
2. The supervisor system prompt in
   `agent/src/graph/nodes/supervisor.ts` (rule "until every pending
   entry has been processed, do not pick synthesize") then forced the
   supervisor LLM to loop through every entry: each iteration picked
   `kickoffExtraction` for the next unprocessed `documentUuid`, the
   pipeline ran, the supervisor was re-invoked, and the pattern
   repeated until the recursion limit bound. The supervisor's own
   iteration cap (`SUPERVISOR_ITERATION_CAP = 10`) was higher than the
   LangGraph default recursion budget once you count the
   supervisor + kickoffExtraction round-trips, so the cap-hit forced-
   synthesize backstop never fired.

There was no signal in the envelope to distinguish "document the
clinician just attached this turn" (load-bearing, must extract) from
"document that's been sitting on the chart since last visit" (best-
effort, only relevant if this turn references it).

## Resolution

Three layered changes in commit `2ff40efba`:

1. **Source tagging.** `PendingUpload` gained
   `source: 'chat-upload' | 'chart-enriched'` and `filename: string |
   null`. The HTTP envelope schema (`agent/src/server/index.ts`)
   tags chat-panel uploads `chat-upload`; `enrichPendingUploads`
   tags its discoveries `chart-enriched` and carries the original
   `documents.name` filename through from a new field on the
   `chart-documents.php` endpoint. The PHP-side adapters
   (`ChartDocumentsDataSource.php`, both interface + production
   implementation) were extended to surface the filename.

2. **Supervisor prompt rule change.** Chat-upload entries still
   auto-extract on the first iteration; chart-enriched entries no
   longer auto-extract. The prompt instructs the supervisor to
   extract a chart-enriched entry only when the typed question
   plausibly references it (filename or doc-type match). Critically,
   chart-enriched entries do **not** block `synthesize`, so a
   default-briefing turn with chart-side docs but no typed question
   reaches the synthesizer in two iterations instead of N+1.

3. **Deterministic visibility cap.** Even if the supervisor model
   ignores the prompt, the observation projection in `observeState`
   hides all but the three most recent chart-enriched entries (chart-
   documents.php already orders newest-first). N-doc fanout is
   structurally bounded to ≤ 3 + chat-uploads per turn — under the
   recursion limit regardless of model behavior.

Regression coverage:
`agent/evals/cases/conversational-graph/chart-enriched-uploads/chartEnrichedFanout.test.ts`
— a naive supervisor stub that mimics the buggy LLM behavior is
applied to a 10-entry chart-enriched envelope and the test asserts
≤ 3 `kickoffExtraction` calls, `capHit === false`, and a rendered
briefing.

## Why CATS didn't catch this earlier / Why it surfaced now

The conversational-graph eval suite stubs `SupervisorDecide` to
deterministic decision sequences and assumes the supervisor returns
within `SUPERVISOR_ITERATION_CAP = 10`. The cap-hit cases that did
exist (`cap-hit/capHit.test.ts`) exercise *stuck-on-retriever* loops,
not *stuck-on-extraction* loops, and they override `iterationCap` to
`3` to keep the test cheap — so they never exercised the case where
the supervisor's own cap is higher than LangGraph's default
`recursionLimit` (25, the real ceiling here once you double-count
supervisor + kickoff edges). The bug needed a real-model decision
*and* multiple un-extracted chart documents on the same patient *and*
no typed question to fire — a combination that nightly LangSmith
runs sample but per-MR Vitest gates didn't. The CATS campaign
exercised it because the campaign's seeded patients carry several
chart-side documents by design and one of the personas triggers a
default-briefing turn with no question. The new regression test
encodes the precise structural invariant (chart-enriched fanout is
bounded) so the per-MR gate now catches it.

## Related

None yet — this is the first entry in `cats/docs/resolved/`. A future
entry should cross-link here if a related supervisor-routing issue
lands.
