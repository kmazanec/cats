"""Campaign worker entrypoint. Builds the graph and drives it for one run.

For scaffold this is a placeholder; `cats smoke` exercises the same code
path with a fixed CampaignState.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from cats.graph.build import build_graph
from cats.graph.state import CampaignState


async def run_one(
    *,
    campaign_id: UUID,
    run_id: UUID,
    project_version_id: UUID,
    smoke_mode: bool = False,
) -> CampaignState:
    graph = build_graph()
    initial = CampaignState(
        run_id=run_id,
        campaign_id=campaign_id,
        project_version_id=project_version_id,
        smoke_mode=smoke_mode,
    )
    result = await graph.ainvoke(
        initial,
        config={"configurable": {"thread_id": str(run_id)}},
    )
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
