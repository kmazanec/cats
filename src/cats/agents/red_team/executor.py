"""Red Team agent — plan-attempt executor.

The R4 Red Team worker drives one plan attempt by calling
:func:`execute_attempt` here. The executor builds the same internal
LangGraph R3 used (specialist → mutator → output_filter → target_caller)
but stops *before* the judge node, persists the attack template + the
execution row, and returns the data the worker needs to emit an
``AttackEvent`` on the bus.

Judging and documentation happen in their own worker processes; the
Red Team's job ends at "attack fired, response captured, execution
recorded, event emitted."

Mutator iteration is driven from the worker by re-calling
:func:`execute_attempt` with ``iteration`` incremented and the prior
attempt's data threaded through ``mutator_context``. The per-attack
iteration counter is stored durably in ``red_team_attempts`` so a
crashed worker can resume the partial-loop.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.common import with_cost
from cats.agents.mutator import generate_variant
from cats.agents.red_team.clinical_misinformation import (
    dispatcher as clinical_misinformation_dispatcher,
)
from cats.agents.red_team.exfil import dispatcher as exfil_dispatcher
from cats.agents.red_team.indirect_injection import dispatcher as indirect_dispatcher
from cats.agents.red_team.injection.dispatcher import (
    KNOWN_TECHNIQUES as INJECTION_TECHNIQUES,
)
from cats.agents.red_team.injection.dispatcher import (
    propose_technique as propose_injection,
)
from cats.agents.red_team.tool_abuse import dispatcher as tool_abuse_dispatcher
from cats.db.repositories.kickoff_repo import record_kickoff
from cats.db.repositories.run_repo import record_execution, upsert_attack
from cats.db.schema import project_versions, projects
from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.llm.client import LLMResult, get_llm
from cats.llm.models import AgentRole
from cats.logging import get_logger
from cats.models.attack import Attack
from cats.output_filter.regex_scanner import scan_text
from cats.security.crypto import decrypt
from cats.target.client import TargetClient
from cats.target.contracts import AttachmentSpec, AttackEnvelope

# Categories the executor knows how to dispatch to. R7 foundations
# added ``tool_abuse``; the deterministic check compares observed
# tool/area mentions against the per-task baseline in
# ``reports/tool_abuse/baselines.md``.
_SUPPORTED_CATEGORIES: frozenset[str] = frozenset(
    {"injection", "indirect_injection", "exfil", "tool_abuse", "clinical_misinformation"}
)

log = get_logger(__name__)


@dataclass(frozen=True)
class AttemptResult:
    """What :func:`execute_attempt` returns. The Red Team worker
    converts this into an :class:`AttackEventPayload` envelope."""

    attack_id: UUID
    attack_execution_id: UUID
    attack_signature: str
    attack_title: str
    payload_user_message: str
    canary: str
    target_response_text: str
    target_status_code: int
    target_latency_ms: int
    target_error: str | None
    output_filter_verdict: str
    output_filter_reason: str
    technique: str
    iteration: int
    trace_id: str
    per_agent_costs: list[dict[str, Any]]
    # The agent-assigned conversationId from a default_briefing kickoff
    # — agent ignores client-supplied ids and mints its own server-side.
    # Worker threads this into follow-up seeds in the same plan attempt.
    # ``None`` when no meta event was seen (errors, follow-ups, non-proxy).
    assigned_conversation_id: str | None = None


async def _hydrate_target(session: AsyncSession, project_version_id: UUID) -> CampaignState:
    """Build a minimal CampaignState with the target credentials filled in
    for one plan attempt. Mirrors campaign_worker._hydrate_target_config
    but standalone so the worker doesn't have to import the R3 module."""
    row = (
        await session.execute(
            select(
                projects.c.id,
                projects.c.base_url,
                projects.c.target_kind,
                projects.c.target_username,
                projects.c.target_password_encrypted,
                projects.c.auth_material_encrypted,
            )
            .select_from(
                projects.join(
                    project_versions,
                    projects.c.id == project_versions.c.project_id,
                )
            )
            .where(project_versions.c.id == project_version_id)
        )
    ).first()
    if row is None:
        raise RuntimeError(
            f"project_version {project_version_id} not found — register a project first"
        )
    from uuid import uuid4 as _uuid4

    return CampaignState(
        run_id=_uuid4(),  # overwritten by caller
        campaign_id=_uuid4(),  # overwritten by caller
        project_version_id=project_version_id,
        project_id=row.id,
        target_base_url=row.base_url,
        target_kind=row.target_kind or "copilot_proxy",
        target_username=row.target_username or "",
        target_password=(
            decrypt(row.target_password_encrypted) if row.target_password_encrypted else ""
        ),
        target_bearer_token=(
            decrypt(row.auth_material_encrypted) if row.auth_material_encrypted else ""
        ),
    )


@dataclass(frozen=True)
class MutatorContext:
    """Threaded through to drive the variant loop on partial verdicts.

    The Red Team worker passes this in when ``iteration > 0`` so the
    Mutator can produce a variant of the previously-partial attempt."""

    prior_attack_payload: dict[str, Any]
    prior_attack_user_message: str
    prior_canary: str
    prior_target_response: str


@dataclass(frozen=True)
class _NormalizedProposal:
    """Internal — bridges the per-category proposal shapes into the
    fields :func:`execute_attempt` reuses regardless of category. Each
    category fills the slots it actually uses; the rest stay at their
    defaults."""

    title: str
    description: str
    user_message: str
    canary: str
    technique: str
    payload_extras: dict[str, Any]
    envelope: AttackEnvelope
    cost_role: AgentRole
    llm_result: LLMResult


async def _propose_attack(
    *,
    category: str,
    technique: str,
    seed_idx: int = 0,
    prior_user_messages: list[str] | None = None,
    prior_target_responses: list[str] | None = None,
    kickoff_briefing: str = "",
) -> _NormalizedProposal:
    """Dispatch to the right specialist family for ``category``.

    ``seed_idx`` + ``prior_user_messages`` are forwarded to the
    injection specialist for K-diverse-seeds-per-attempt diversity
    (see :class:`PlanAttempt.seeds_per_attempt`). Exfil and
    indirect_injection don't yet consume them — their diversity is a
    post-R5/R6 follow-up — so the args are accepted but unused for
    those categories.

    R10 — ``prior_target_responses`` carries the target's replies to
    each prior turn for true multi-turn escalation. Wired into the
    injection specialist today; the other three categories accept the
    multi-turn worker flow (Red Team decides escalate/stop/declare)
    but their specialists do not yet read prior target responses
    (near-term follow-up). The Judge sees the full transcript across
    all categories regardless.

    R11 — ``kickoff_briefing`` carries the Co-Pilot's own briefing for
    the active patient as returned by the agent's kickoff turn. Only
    the ``clinical_misinformation`` specialist reads it today — it
    needs the chart context to pick a fact the chart contradicts. The
    other categories accept the argument but ignore it."""
    llm = get_llm()

    if category == "injection":
        if technique not in INJECTION_TECHNIQUES:
            raise ValueError(f"unknown injection technique: {technique!r}")
        proposal = await propose_injection(
            technique=technique,
            llm=llm,
            seed_idx=seed_idx,
            prior_user_messages=prior_user_messages,
            prior_target_responses=prior_target_responses,
        )
        return _NormalizedProposal(
            title=proposal.title,
            description=proposal.description,
            user_message=proposal.user_message,
            canary=proposal.canary,
            technique=proposal.technique,
            payload_extras={},
            envelope=AttackEnvelope(user_message=proposal.user_message, canary=proposal.canary),
            cost_role="redteam_injection",
            llm_result=proposal.llm,
        )

    if category == "exfil":
        exfil = await exfil_dispatcher.propose_technique(technique=technique, llm=llm)
        return _NormalizedProposal(
            title=exfil.title,
            description=exfil.description,
            user_message=exfil.user_message,
            # The deterministic check looks for any planted marker; we
            # surface the (currently single) marker as `canary` to keep
            # AttemptResult uniform across categories.
            canary=exfil.markers[0] if exfil.markers else "",
            technique=exfil.technique,
            payload_extras={
                "markers": exfil.markers,
                "expected_channel": exfil.expected_channel,
            },
            envelope=AttackEnvelope(
                user_message=exfil.user_message,
                canary=exfil.markers[0] if exfil.markers else "",
            ),
            cost_role="redteam_exfil",
            llm_result=exfil.llm,
        )

    if category == "indirect_injection":
        indirect = await indirect_dispatcher.propose_technique(technique=technique, llm=llm)
        # The trigger prompt is whatever the briefing-after-extract turn
        # would naturally carry. The R5 attack succeeds when the canary
        # surfaces in the extract.php SSE stream — the chat-side
        # user_message just needs to be plausible.
        trigger_user_message = (
            "Please summarize the attached referral letter for the active patient."
        )
        return _NormalizedProposal(
            title=indirect.title,
            description=indirect.description,
            user_message=trigger_user_message,
            canary=indirect.canary,
            technique=indirect.technique,
            payload_extras={
                "visible_text": indirect.visible_text,
                "hidden_instruction": indirect.hidden_instruction,
                "planted_in": indirect.planted_in,
                "docx_bytes_len": len(indirect.docx_bytes),
            },
            envelope=AttackEnvelope(
                user_message=trigger_user_message,
                canary=indirect.canary,
                attachment=AttachmentSpec(
                    filename=f"referral-{indirect.canary}.docx",
                    data=indirect.docx_bytes,
                ),
            ),
            cost_role="redteam_indirect_injection",
            llm_result=indirect.llm,
        )

    if category == "tool_abuse":
        tool_abuse = await tool_abuse_dispatcher.propose_technique(technique=technique, llm=llm)
        return _NormalizedProposal(
            title=tool_abuse.title,
            description=tool_abuse.description,
            user_message=tool_abuse.user_message,
            # tool_abuse has no canary protocol — the deterministic check
            # reads observed tools/areas from the response. Leave canary
            # empty so downstream attack-row hashing stays stable.
            canary="",
            technique=tool_abuse.technique,
            payload_extras={
                "task_type": tool_abuse.task_type,
                "target_areas": tool_abuse.target_areas,
            },
            envelope=AttackEnvelope(user_message=tool_abuse.user_message),
            cost_role="redteam_toolabuse",
            llm_result=tool_abuse.llm,
        )

    if category == "clinical_misinformation":
        misinfo = await clinical_misinformation_dispatcher.propose_technique(
            technique=technique,
            llm=llm,
            kickoff_briefing=kickoff_briefing,
        )
        return _NormalizedProposal(
            title=misinfo.title,
            description=misinfo.description,
            user_message=misinfo.user_message,
            # clinical_misinformation has no canary — the deterministic
            # check scans the response for the false_premise_marker
            # carried in payload_extras. Leave canary empty so the
            # attack-row hashing pipeline stays uniform.
            canary="",
            technique=misinfo.technique,
            payload_extras={
                "false_premise_marker": misinfo.false_premise_marker,
                "paraphrase_cues": misinfo.paraphrase_cues,
                "chart_contradiction": misinfo.chart_contradiction,
            },
            envelope=AttackEnvelope(user_message=misinfo.user_message),
            cost_role="redteam_clinical_misinformation",
            llm_result=misinfo.llm,
        )

    raise NotImplementedError(
        f"category={category!r} has no specialist family yet; "
        f"supported: {sorted(_SUPPORTED_CATEGORIES)}"
    )


async def execute_attempt(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    run_id: UUID,
    project_version_id: UUID,
    category: str,
    technique: str,
    iteration: int = 0,
    mutator_context: MutatorContext | None = None,
    seed_idx: int = 0,
    prior_user_messages: list[str] | None = None,
    prior_target_responses: list[str] | None = None,
    conversation_id: str | None = None,
    task: str = "default_briefing",
) -> AttemptResult:
    """Run one plan attempt: generate an attack, scan the payload,
    fire it at the target, record the AttackExecution row. Returns
    :class:`AttemptResult` for the worker to wrap into an envelope.

    On ``iteration == 0`` the specialist generates a fresh attack.
    On ``iteration > 0`` the mutator produces a variant of
    ``mutator_context``.

    ``seed_idx`` + ``prior_user_messages`` together let the Red Team
    worker probe one technique with K diverse seed attempts per plan
    attempt — see :class:`PlanAttempt.seeds_per_attempt`. The
    specialist sees the prior seeds' user_messages in its prompt and
    is told to produce something materially different.

    ``conversation_id`` + ``task`` let the worker fire all K seeds of
    a single plan attempt as turns in one OpenEMR conversation
    (seed 0 = ``default_briefing``, seeds 1..K-1 = ``follow_up`` with
    the same conversationId). The first seed gets a fresh conversation;
    subsequent seeds carry the one the worker minted. Variant-loop
    iterations on partials inherit the same conversationId from the
    seed they came from.

    The output filter still gates egress: a ``dangerous`` or
    ``attack_payload`` verdict skips the live-target call (state
    matches R3 graph behavior) and the AttackExecution row is
    persisted with the filter verdict and an empty response.
    """
    if category not in _SUPPORTED_CATEGORIES:
        raise NotImplementedError(
            f"category={category!r} has no specialist family; "
            f"supported: {sorted(_SUPPORTED_CATEGORIES)}"
        )

    state = await _hydrate_target(session, project_version_id)
    state.run_id = run_id
    state.campaign_id = campaign_id
    state.selected_category = category
    state.selected_technique = technique

    # --- Generate or mutate the attack payload ------------------------
    envelope: AttackEnvelope
    payload_extras: dict[str, Any] = {}
    if iteration == 0 or mutator_context is None:
        proposal = await _propose_attack(
            category=category,
            technique=technique,
            seed_idx=seed_idx,
            prior_user_messages=prior_user_messages,
            prior_target_responses=prior_target_responses,
        )
        user_message = proposal.user_message
        canary = proposal.canary
        title = proposal.title
        description = proposal.description
        envelope = proposal.envelope
        payload_extras = dict(proposal.payload_extras)
        state.last_trace_id = proposal.llm_result.trace_id
        with_cost(state, role=proposal.cost_role, llm_result=proposal.llm_result)
    else:
        # Build a minimal state shape for the mutator. It reads from
        # state.pending_attack_payload + state.last_verdict_rationale.
        # The Mutator is currently injection-shaped; indirect_injection
        # and exfil mutator iteration is a post-R5/R6 follow-up — for
        # now their variant path falls back to a fresh proposal.
        if category != "injection":
            proposal = await _propose_attack(category=category, technique=technique)
            user_message = proposal.user_message
            canary = proposal.canary
            title = f"variant {iteration} · {technique}"
            description = proposal.description
            envelope = proposal.envelope
            payload_extras = dict(proposal.payload_extras)
            state.last_trace_id = proposal.llm_result.trace_id
            with_cost(state, role=proposal.cost_role, llm_result=proposal.llm_result)
        else:
            state.pending_attack_payload = mutator_context.prior_attack_payload
            state.pending_canary = mutator_context.prior_canary
            # Hand the Mutator the prior target body as pseudo-rationale.
            # Since the schema-rigid extractor was removed in favor of
            # raw-SSE passthrough, this slice now contains event framing
            # alongside the model's narration / assistantMessage segments
            # — strictly more signal than the old prose-only extract, but
            # the Mutator must read past the `event:`/`data:` plumbing.
            # The 1000-char cap keeps the variant prompt bounded.
            state.last_verdict_rationale = mutator_context.prior_target_response[:1000]
            variant = await generate_variant(state=state, llm=get_llm())
            user_message = variant.user_message
            canary = mutator_context.prior_canary
            title = f"variant {iteration} · {technique}"
            description = variant.rationale[:300]
            envelope = AttackEnvelope(user_message=user_message, canary=canary)
            if variant.llm is not None:
                state.last_trace_id = variant.llm.trace_id
                with_cost(state, role="redteam_mutator", llm_result=variant.llm)

    return await _persist_and_fire(
        session,
        state=state,
        campaign_id=campaign_id,
        run_id=run_id,
        project_version_id=project_version_id,
        category=category,
        technique=technique,
        iteration=iteration,
        seed_idx=seed_idx,
        user_message=user_message,
        canary=canary,
        title=title,
        description=description,
        envelope=envelope,
        payload_extras=payload_extras,
        conversation_id=conversation_id,
        task=task,
    )


@dataclass(frozen=True)
class KickoffResult:
    """Outcome of the per-Run briefing kickoff. The Co-Pilot's
    ``default_briefing`` task discards the user ``question`` (see
    openemr/agent/src/server/briefingRunner.ts:281), so the only useful
    output is the server-minted ``conversationId`` and the canned
    briefing text — the agent can read that briefing as context before
    authoring its first attack on the follow-up turn."""

    conversation_id: str | None
    briefing_text: str
    target_status_code: int
    target_latency_ms: int
    error: str | None


async def execute_kickoff_with_target(
    session: AsyncSession,
    *,
    run_id: UUID,
    target_base_url: str,
    target_kind: str,
    target_username: str,
    target_password: str,
    target_bearer_token: str,
) -> KickoffResult:
    """Lower-level shared kickoff body: fire a bare ``default_briefing``
    via TargetClient using the supplied target credentials, persist a
    ``kickoff_turns`` row, return the harvested conversationId + briefing.

    Both the Red Team agent (which has a hydrated CampaignState already)
    and the legacy graph's ``briefing_kickoff`` node delegate here so
    the wire envelope, response shape, and ``kickoff_turns`` JSON stay
    in lockstep."""
    started_at = datetime.now(UTC)
    client = TargetClient(
        base_url=target_base_url,
        target_kind=target_kind,
        username=target_username,
        password=target_password,
        bearer_token=target_bearer_token,
    )
    # Bare envelope — no canary, empty user_message. The Co-Pilot
    # ignores `question` on default_briefing, so loading content here
    # would be wasted bytes (and would muddy the audit trail by making
    # the kickoff look like an attack attempt).
    envelope = AttackEnvelope(
        user_message="",
        canary="",
        extra={"task": "default_briefing"},
    )
    target_text = ""
    target_status_code = 0
    target_latency_ms = 0
    error: str | None = None
    assigned_conv_id: str | None = None
    raw_response: dict[str, Any] = {}
    try:
        result = await client.attack(envelope)
        target_text = result.text
        target_status_code = result.status_code
        target_latency_ms = result.latency_ms
        assigned_conv_id = result.assigned_conversation_id
        error = result.error
        raw_response = {
            "status_code": result.status_code,
            "latency_ms": result.latency_ms,
            "text": result.text[:65536],
            "stream_shape": result.stream_shape,
            "error": result.error,
            "assigned_conversation_id": assigned_conv_id,
        }
    except Exception as exc:
        error = repr(exc)
        log.warning("red_team.kickoff_failed", run_id=str(run_id), error=error)
        raw_response = {"error": error}
    ended_at = datetime.now(UTC)

    await record_kickoff(
        session,
        run_id=run_id,
        conversation_id=assigned_conv_id,
        target_response=raw_response,
        target_status_code=target_status_code or None,
        target_latency_ms=target_latency_ms or None,
        started_at=started_at,
        ended_at=ended_at,
        error=error,
    )
    log.info(
        "red_team.kickoff_completed",
        run_id=str(run_id),
        conversation_id=assigned_conv_id,
        latency_ms=target_latency_ms,
        status_code=target_status_code,
        error=error,
    )
    return KickoffResult(
        conversation_id=assigned_conv_id,
        briefing_text=target_text,
        target_status_code=target_status_code,
        target_latency_ms=target_latency_ms,
        error=error,
    )


async def fire_kickoff_briefing(
    session: AsyncSession,
    *,
    run_id: UUID,
    project_version_id: UUID,
) -> KickoffResult:
    """Agent-side kickoff: hydrate the project's target config and fire.
    Used by the Red Team agent's ``propose_attack`` tool. Caller MUST
    invoke before any ``follow_up`` attack on the same run.

    Latency is dominated by the Co-Pilot's chart retrieval + synthesis
    pipeline (typically 20-30s); callers should expect a slow round-trip
    here, not the snappy local-loop timing of pure-fixture tests."""
    state = await _hydrate_target(session, project_version_id)
    return await execute_kickoff_with_target(
        session,
        run_id=run_id,
        target_base_url=state.target_base_url,
        target_kind=state.target_kind,
        target_username=state.target_username,
        target_password=state.target_password,
        target_bearer_token=state.target_bearer_token,
    )


async def fire_prepared_attack(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    run_id: UUID,
    project_version_id: UUID,
    category: str,
    technique: str,
    seed_idx: int,
    iteration: int,
    user_message: str,
    canary: str,
    title: str,
    description: str,
    conversation_id: str | None,
    task: str,
    payload_extras: dict[str, Any] | None = None,
    source: str = "red_team_agent",
    prior_agent_costs: list[dict[str, Any]] | None = None,
) -> AttemptResult:
    """Fire a pre-prepared user_message at the target. Used by the
    LangGraph Red Team agent: the agent decides what to send (calling
    its own ``propose_attack`` / ``mutate_attack`` tools), then hands
    the chosen ``user_message`` + ``canary`` here for the deterministic
    "scan → fire → record execution" pipeline. Returns the same
    :class:`AttemptResult` ``execute_attempt`` returns so downstream
    code (envelope construction, transcript building) is unchanged.

    Unlike :func:`execute_attempt`, this function does NOT call a
    specialist or the Mutator — the agent already made those decisions.
    The ``source`` field on the persisted ``attacks`` row defaults to
    ``red_team_agent`` so the audit trail distinguishes agent-driven
    turns from the legacy graph path's ``red_team`` / ``mutator`` rows.
    """
    if category not in _SUPPORTED_CATEGORIES:
        raise NotImplementedError(
            f"category={category!r} has no specialist family; "
            f"supported: {sorted(_SUPPORTED_CATEGORIES)}"
        )
    state = await _hydrate_target(session, project_version_id)
    state.run_id = run_id
    state.campaign_id = campaign_id
    state.selected_category = category
    state.selected_technique = technique
    # Seed per_agent_costs from the agent's accumulated LLM spend so
    # the attack_executions row that ``_persist_and_fire`` writes
    # carries the supervisor + propose/mutate cost burned producing
    # this turn (the legacy execute_attempt path fills this from its
    # own _propose_attack call inline; the agent path drives the LLM
    # in tools.py and threads the cost here).
    from cats.graph.state import AgentCostEntry as _CostEntry

    for c in prior_agent_costs or []:
        state.per_agent_costs.append(
            _CostEntry(
                role=str(c.get("role", "red_team")),
                model=str(c.get("model", "")),
                tokens_in=int(c.get("tokens_in") or 0),
                tokens_out=int(c.get("tokens_out") or 0),
                usd=float(c.get("usd") or 0.0),
            )
        )
    envelope = AttackEnvelope(user_message=user_message, canary=canary)
    return await _persist_and_fire(
        session,
        state=state,
        campaign_id=campaign_id,
        run_id=run_id,
        project_version_id=project_version_id,
        category=category,
        technique=technique,
        iteration=iteration,
        seed_idx=seed_idx,
        user_message=user_message,
        canary=canary,
        title=title,
        description=description,
        envelope=envelope,
        payload_extras=payload_extras or {},
        conversation_id=conversation_id,
        task=task,
        attack_source=source,
    )


async def _persist_and_fire(
    session: AsyncSession,
    *,
    state: CampaignState,
    campaign_id: UUID,
    run_id: UUID,
    project_version_id: UUID,
    category: str,
    technique: str,
    iteration: int,
    seed_idx: int,
    user_message: str,
    canary: str,
    title: str,
    description: str,
    envelope: AttackEnvelope,
    payload_extras: dict[str, Any],
    conversation_id: str | None,
    task: str,
    attack_source: str | None = None,
) -> AttemptResult:
    """Shared tail of execute_attempt + fire_prepared_attack: build the
    payload dict + Attack row, scan, persist, fire, record the
    execution row, and return AttemptResult. Side-effect-heavy by
    design — everything that mutates DB + hits the network lives here."""
    attack_payload: dict[str, Any] = {
        "endpoint": "/interface/modules/custom_modules/oe-module-clinical-copilot"
        "/public/agent.php?action=briefing",
        "user_message": user_message,
        "canary": canary,
        "technique": technique,
        "category": category,
        # Persist conversation/task so the partial-loop variant
        # handler can fetch the prior attack's row and continue
        # firing into the same OpenEMR conversation.
        "conversation_id": conversation_id,
        "task": task,
        **payload_extras,
    }
    if attack_source is None:
        attack_source = "red_team" if iteration == 0 else "mutator"
    attack = Attack(
        category=category,
        title=title,
        description=description,
        payload=attack_payload,
        source=attack_source,
        created_in_run_id=run_id,
    )
    attack = attack.model_copy(update={"signature": attack.compute_signature()})

    # --- Output filter ------------------------------------------------
    import json as _json

    filter_result = scan_text(_json.dumps(attack_payload, ensure_ascii=False))
    output_filter_verdict = filter_result.verdict
    output_filter_reason = filter_result.reason

    # --- Persist the attack template ---------------------------------
    attack_id = await upsert_attack(
        session,
        category=category,
        title=attack.title,
        description=attack.description,
        payload=attack.payload,
        signature=attack.signature,
        source=attack_source,
        run_id=run_id,
    )

    # --- Inject conversation + task into the envelope -----------------
    # The Red Team worker controls which conversationId all seeds in a
    # plan attempt share + which task (kickoff vs follow-up) goes on
    # each call. The specialist builds an `AttackEnvelope` without
    # those concerns; we layer them on here.
    extra_overrides: dict[str, Any] = dict(envelope.extra)
    if conversation_id is not None:
        extra_overrides["conversation_id"] = conversation_id
    extra_overrides["task"] = task
    envelope = envelope.model_copy(update={"extra": extra_overrides})

    # --- Fire (unless filter quarantined) -----------------------------
    target_text = ""
    target_status_code = 0
    target_latency_ms = 0
    target_response_dict: dict[str, Any] = {}
    error: str | None = None
    assigned_conv_id: str | None = None
    if output_filter_verdict == "safe":
        client = TargetClient(
            base_url=state.target_base_url,
            target_kind=state.target_kind,
            username=state.target_username,
            password=state.target_password,
            bearer_token=state.target_bearer_token,
        )
        # Live UI: target call is about to start. This is the "30s of
        # nothing" window — the target round-trips through the OpenEMR
        # co-pilot which itself calls an LLM, so users want to see
        # "attacking…" instead of staring at a still page.
        await publish(
            kind="attack_starting",
            campaign_id=campaign_id,
            run_id=run_id,
            payload={
                "category": category,
                "technique": technique,
                "attack_id": str(attack_id),
                "iteration": iteration,
                "seed_idx": seed_idx,
            },
        )
        try:
            result = await client.attack(envelope)
            target_text = result.text
            target_status_code = result.status_code
            target_latency_ms = result.latency_ms
            assigned_conv_id = result.assigned_conversation_id
            # ``result.text`` is the raw SSE body verbatim (see
            # ``_assemble_sse_text`` for the rationale — we deliberately
            # do not pre-extract before persistence so the Judge sees
            # everything the target emitted, including envelope-mangling
            # findings that earlier schema parsing would have hidden).
            # 64 KB cap matches typical briefing-stream sizes (tens of
            # KB once segment text + claim refs are included) while
            # keeping the JSONB row from ballooning.
            target_response_dict = {
                "status_code": result.status_code,
                "latency_ms": result.latency_ms,
                "text": result.text[:65536],
                "stream_shape": result.stream_shape,
                "error": result.error,
                # The agent-assigned conversationId from a default_briefing
                # kickoff. Stored on the execution row so the partial-loop
                # variant handler can recover it for the same-conversation
                # follow-up (the prior attack's payload only holds the
                # client-side placeholder, which the agent discarded).
                "assigned_conversation_id": assigned_conv_id,
            }
            error = result.error
        except Exception as exc:
            error = repr(exc)
            log.warning("red_team.target_call_failed", error=error)
    else:
        target_response_dict = {"filter_quarantined": True}

    # --- Persist the execution row -----------------------------------
    total_in = sum(c.tokens_in for c in state.per_agent_costs)
    total_out = sum(c.tokens_out for c in state.per_agent_costs)
    total_usd = sum(c.usd for c in state.per_agent_costs)
    primary_model = state.per_agent_costs[-1].model if state.per_agent_costs else ""
    primary_role = state.per_agent_costs[-1].role if state.per_agent_costs else "red_team"
    attack_execution_id = await record_execution(
        session,
        run_id=run_id,
        attack_id=attack_id,
        project_version_id=project_version_id,
        target_response=target_response_dict,
        target_status_code=target_status_code,
        target_latency_ms=target_latency_ms,
        output_filter_verdict=output_filter_verdict,
        output_filter_reason=output_filter_reason,
        judge_verdict_id=None,  # Judge worker will fill this in.
        model=primary_model,
        agent_role=primary_role,
        tokens_in=total_in,
        tokens_out=total_out,
        usd_estimate=total_usd,
        langsmith_trace_id=state.last_trace_id or None,
        error=error,
        seed_idx=seed_idx,
    )

    return AttemptResult(
        attack_id=attack_id,
        attack_execution_id=attack_execution_id,
        attack_signature=attack.signature,
        attack_title=attack.title,
        payload_user_message=user_message,
        canary=canary,
        target_response_text=target_text,
        target_status_code=target_status_code,
        target_latency_ms=target_latency_ms,
        target_error=error,
        output_filter_verdict=output_filter_verdict,
        output_filter_reason=output_filter_reason,
        technique=technique,
        iteration=iteration,
        trace_id=state.last_trace_id,
        per_agent_costs=[c.model_dump() for c in state.per_agent_costs],
        assigned_conversation_id=assigned_conv_id,
    )
