"""End-to-end no-LLM smoke path.

R1 had this CLI persisting the chain directly via `smoke_repo` after
the graph ran. R2's Documentation node owns the writes, so this CLI
just sets up the Project / Campaign / Run skeleton and invokes the
worker — the graph fills in Attack / AttackExecution / JudgeVerdict
/ Finding rows.
"""

from __future__ import annotations

from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.smoke_repo import (
    create_campaign,
    create_run,
    upsert_project,
    upsert_project_version,
)
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

    logger.info(
        "smoke.complete",
        run=str(run_id),
        verdict=state.last_verdict,
        finding=str(state.finding_id) if state.finding_id else None,
    )
    return state
