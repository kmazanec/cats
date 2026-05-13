"""Legacy R3 campaign worker — used only by the smoke CLI and the
R3-shaped e2e tests that drive one Run end-to-end via the LangGraph.

R4's bus-mediated worker pipeline lives in
:mod:`cats.workers.{orchestrator,red_team,judge,documentation}`. Do
NOT reach for this module in new code; it stays because:

1. ``cats smoke`` exercises the in-memory-checkpointer graph without
   spinning up the bus — useful as a no-Redis, no-LLM sanity check.
2. The R3 ``test_campaign_e2e`` covers the domain pass-path through
   ``run_one`` so changes to the graph nodes still surface there.

R3's ``run_campaign_multi_technique`` driver was removed in R4 —
the four-worker bus pipeline replaces it. Multi-technique campaigns
are now driven by the Orchestrator's ``CampaignPlan``.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from sqlalchemy import select

from cats.db.engine import session_scope
from cats.db.repositories.run_repo import mark_run_running
from cats.db.schema import project_versions, projects
from cats.graph.build import build_graph
from cats.graph.checkpointer import postgres_checkpointer
from cats.graph.state import CampaignState
from cats.logging import get_logger
from cats.security.crypto import decrypt

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
