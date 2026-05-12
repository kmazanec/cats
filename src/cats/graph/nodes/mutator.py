"""Mutator node.

R2 scope: the Mutator is present and visible in the campaign view but
does not generate variants yet. The round's "out of scope" list
explicitly defers real variant generation; R3 is where it lands.

This node passes the attack through unchanged and publishes a
`mutator_passthrough` event so the dashboard reflects that the role
exists and is being exercised — just trivially this round.
"""

from __future__ import annotations

from cats.graph.events import publish
from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    await publish(
        kind="attack_proposed",  # reuse the kind; payload disambiguates
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "stage": "mutator_passthrough",
            "note": "R2 ships the Mutator role as passthrough; real "
            "variant generation lands in R3.",
        },
    )
    return state
