"""Campaign worker. Builds the graph, hydrates the initial state with
project credentials, and drives it for one run.

`run_one` is the main entrypoint:
- Smoke mode: in-memory checkpointer, no Postgres saver, skips
  credential lookup. Used by `cats smoke`.
- Real runs: AsyncPostgresSaver, project credentials loaded from
  `projects` table and decrypted. Resume from the last checkpoint is
  automatic — same `thread_id` on a second call picks up where the
  previous attempt left off.
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
) -> CampaignState:
    """Drive one Run end-to-end. Idempotent on `thread_id = str(run_id)`."""

    async with session_scope() as session:
        await mark_run_running(session, run_id=run_id)

    initial = CampaignState(
        run_id=run_id,
        campaign_id=campaign_id,
        project_version_id=project_version_id,
        smoke_mode=smoke_mode,
        selected_category=selected_category,
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
