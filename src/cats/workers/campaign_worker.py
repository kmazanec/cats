"""Campaign worker. Builds the graph, hydrates the initial state with
project credentials, and drives it for one run.

``run_one`` runs the graph end-to-end for a single attack (one Run).
``run_campaign_multi_technique`` is the R3 driver that issues several
Runs against one Campaign, each pinned to a different injection
technique from :data:`MIN_TECHNIQUES_PER_CAMPAIGN`.

- Smoke mode: in-memory checkpointer, no Postgres saver, skips
  credential lookup. Used by ``cats smoke``.
- Real runs: AsyncPostgresSaver, project credentials loaded from
  ``projects`` table and decrypted. Resume from the last checkpoint is
  automatic — same ``thread_id`` on a second call picks up where the
  previous attempt left off.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from sqlalchemy import select

from cats.agents.red_team.injection.dispatcher import ROTATION as INJECTION_ROTATION
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_run_in_campaign
from cats.db.repositories.run_repo import mark_run_running
from cats.db.schema import project_versions, projects
from cats.graph.build import build_graph
from cats.graph.checkpointer import postgres_checkpointer
from cats.graph.state import CampaignState
from cats.logging import get_logger
from cats.security.crypto import decrypt

# R3 DoD: "a single campaign visibly exercises multiple distinct
# techniques." Set to 3 — enough to demonstrate the family-of-attacks
# behavior without burning the budget on every fire. Configurable per
# campaign via the ``num_techniques`` arg.
MIN_TECHNIQUES_PER_CAMPAIGN: int = 3

log = get_logger(__name__)


async def _hydrate_target_config(state: CampaignState) -> CampaignState:
    """Load Project target config off the DB and populate state. Done
    once at run start so per-node DB hits are avoided."""
    async with session_scope() as session:
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
                .where(project_versions.c.id == state.project_version_id)
            )
        ).first()
    if row is None:
        raise RuntimeError(
            f"project_version {state.project_version_id} not found — register a project first"
        )
    state.project_id = row.id
    state.target_base_url = row.base_url
    state.target_kind = row.target_kind or "copilot_proxy"
    state.target_username = row.target_username or ""
    state.target_password = (
        decrypt(row.target_password_encrypted) if row.target_password_encrypted else ""
    )
    state.target_bearer_token = (
        decrypt(row.auth_material_encrypted) if row.auth_material_encrypted else ""
    )
    return state


async def run_one(
    *,
    campaign_id: UUID,
    run_id: UUID,
    project_version_id: UUID,
    smoke_mode: bool = False,
    selected_category: str = "injection",
    selected_technique: str = "",
) -> CampaignState:
    """Drive one Run end-to-end. Idempotent on `thread_id = str(run_id)`.

    Pass ``selected_technique`` to pin the Red Team specialist to a
    specific technique (R3). Empty string means the dispatcher picks
    via its rotation policy.
    """

    async with session_scope() as session:
        await mark_run_running(session, run_id=run_id)

    initial = CampaignState(
        run_id=run_id,
        campaign_id=campaign_id,
        project_version_id=project_version_id,
        smoke_mode=smoke_mode,
        selected_category=selected_category,
        selected_technique=selected_technique,
    )
    if not smoke_mode:
        initial = await _hydrate_target_config(initial)

    config: dict[str, Any] = {"configurable": {"thread_id": str(run_id)}}

    if smoke_mode:
        # In-memory saver; the smoke path doesn't need cross-process
        # checkpointing.
        graph = build_graph()
        result = await graph.ainvoke(initial, config=config)
    else:
        async with postgres_checkpointer() as saver:
            graph = build_graph(checkpointer=saver)
            result = await graph.ainvoke(initial, config=config)

    if isinstance(result, CampaignState):
        return result
    return CampaignState.model_validate(result)


async def run_campaign_multi_technique(
    *,
    campaign_id: UUID,
    first_run_id: UUID,
    project_version_id: UUID,
    num_techniques: int = MIN_TECHNIQUES_PER_CAMPAIGN,
    selected_category: str = "injection",
) -> list[CampaignState]:
    """R3 — issue ``num_techniques`` consecutive Runs against the
    campaign, each pinned to a different technique from the dispatcher's
    rotation. The first Run uses ``first_run_id`` (already created by
    the caller); subsequent Runs are created here.

    Returns the list of final states (one per Run). Errors in any one
    Run are logged but don't halt the campaign — the caller can inspect
    ``state.halted_reason`` per state.

    Only injection is multi-technique right now; other categories run
    a single Run (R2 behavior preserved).
    """
    rotation = INJECTION_ROTATION if selected_category == "injection" else ("",)
    techniques = list(rotation[: max(1, num_techniques)])

    states: list[CampaignState] = []
    for idx, technique in enumerate(techniques):
        if idx == 0:
            run_id = first_run_id
        else:
            async with session_scope() as session:
                run_id = await create_run_in_campaign(
                    session,
                    campaign_id=campaign_id,
                    project_version_id=project_version_id,
                )

        try:
            state = await run_one(
                campaign_id=campaign_id,
                run_id=run_id,
                project_version_id=project_version_id,
                smoke_mode=False,
                selected_category=selected_category,
                selected_technique=technique,
            )
            states.append(state)
        except Exception as exc:
            log.exception(
                "campaign.run_failed",
                campaign_id=str(campaign_id),
                run_id=str(run_id),
                technique=technique,
                error=repr(exc),
            )
    return states


def main() -> None:
    from uuid import uuid4

    asyncio.run(
        run_one(
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            smoke_mode=True,
        )
    )


if __name__ == "__main__":
    main()
