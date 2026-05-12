"""End-to-end no-LLM smoke path.

Builds the graph, runs it in smoke_mode (canned target response, no
OpenRouter), and persists the full chain:

    Project → ProjectVersion → Campaign → Run →
        Attack → AttackExecution → JudgeVerdict → Finding

Also publishes one SSE event so the dashboard wiring is exercised end-to-end.
"""

from __future__ import annotations

from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.smoke_repo import (
    complete_run,
    create_campaign,
    create_run,
    link_finding_execution,
    record_attack_execution,
    record_verdict,
    upsert_attack,
    upsert_finding,
    upsert_project,
    upsert_project_version,
)
from cats.events.bus import EventBus
from cats.events.types import EventEnvelope
from cats.graph.state import CampaignState
from cats.logging import configure_logging, get_logger
from cats.workers.campaign_worker import run_one

logger = get_logger(__name__)


async def run_smoke(*, target_url: str | None = None) -> CampaignState:
    configure_logging()
    base_url = target_url or settings.default_target_base_url

    async with session_scope() as session:
        project_id = await upsert_project(
            session,
            name=settings.default_target_name,
            base_url=base_url,
            env=settings.default_target_env,
        )
        project_version_id = await upsert_project_version(
            session,
            project_id=project_id,
            label="smoke-seed",
        )
        campaign_id = await create_campaign(session, name="smoke", project_id=project_id)
        run_id = await create_run(
            session, campaign_id=campaign_id, project_version_id=project_version_id
        )

    logger.info("smoke.seeded", project=str(project_id), run=str(run_id))

    state = await run_one(
        campaign_id=campaign_id,
        run_id=run_id,
        project_version_id=project_version_id,
        smoke_mode=True,
    )

    target_response = state.last_target_response
    verdict_label = state.last_verdict or "partial"

    async with session_scope() as session:
        attack_id = await upsert_attack(
            session,
            category=state.selected_category or "injection",
            title=state.pending_attack_title or "smoke probe",
            payload=state.pending_attack_payload,
            signature=state.pending_attack_signature or "smoke",
            source="seed",
        )
        verdict_id = await record_verdict(
            session,
            verdict=verdict_label,
            is_deterministic=True,
            rationale=str(target_response.get("judge_rationale", "")),
            evidence=dict(target_response.get("judge_evidence", {})),
            judge_model="deterministic",
        )
        execution_id = await record_attack_execution(
            session,
            run_id=run_id,
            attack_id=attack_id,
            project_version_id=project_version_id,
            target_response=target_response,
            judge_verdict_id=verdict_id,
            model="smoke",
        )
        finding_id = await upsert_finding(
            session,
            run_id=run_id,
            category=state.selected_category or "injection",
            signature=state.pending_attack_signature or "smoke",
            title=f"[smoke] {state.pending_attack_title}",
            severity="info",
            summary="Scaffold smoke finding. No real exploit; demonstrates the write path.",
        )
        await link_finding_execution(
            session, finding_id=finding_id, attack_execution_id=execution_id
        )
        await complete_run(session, run_id=run_id)

    bus = EventBus()
    try:
        await bus.publish(
            EventEnvelope(
                kind="finding_promoted",
                campaign_id=campaign_id,
                run_id=run_id,
                payload={
                    "finding_id": str(finding_id),
                    "attack_id": str(attack_id),
                    "execution_id": str(execution_id),
                    "verdict": verdict_label,
                },
            )
        )
    finally:
        await bus.close()

    logger.info(
        "smoke.complete",
        run=str(run_id),
        finding=str(finding_id),
        verdict=verdict_label,
    )
    return state
