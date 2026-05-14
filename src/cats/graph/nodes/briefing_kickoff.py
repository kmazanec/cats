"""Briefing Kickoff node.

Fires one bare ``default_briefing`` against the live target before any
attack runs, harvests the server-minted ``conversationId``, and
persists a ``kickoff_turns`` row. Every downstream attack rides on that
conversationId as ``task=follow_up`` — without it the Co-Pilot would
discard the attack's ``question`` field (it ignores ``question`` on
``default_briefing``; see openemr/agent/src/server/briefingRunner.ts:281).

Smoke mode skips the kickoff entirely — the canned target_caller
response is what the test asserts on, and exercising real briefing
HTTP would defeat the no-network promise of the smoke path.

Delegates to :func:`cats.agents.red_team.executor.execute_kickoff_with_target`
for the wire envelope + persistence so the legacy graph and the agent
path can't drift on response shape.
"""

from __future__ import annotations

from cats.agents.red_team.executor import execute_kickoff_with_target
from cats.db.engine import session_scope
from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.logging import get_logger

log = get_logger(__name__)


async def run(state: CampaignState) -> CampaignState:
    if state.smoke_mode:
        return state
    if not state.target_base_url:
        # Without a target URL the run can't fire anything; downstream
        # nodes already short-circuit on the same condition. Recording
        # an empty kickoff row would just clutter the table.
        return state

    async with session_scope() as session:
        result = await execute_kickoff_with_target(
            session,
            run_id=state.run_id,
            target_base_url=state.target_base_url,
            target_kind=state.target_kind,
            target_username=state.target_username,
            target_password=state.target_password,
            target_bearer_token=state.target_bearer_token,
        )

    state.kickoff_conversation_id = result.conversation_id or ""
    if result.conversation_id is None:
        # Loud signal: downstream target_caller will fall back to
        # default_briefing (which the Co-Pilot answers with the canned
        # body, ignoring `question`). The attack execution row will
        # still be persisted, but it's effectively a wasted probe —
        # operators should treat run-detail bubbles after a failed
        # kickoff with extra suspicion.
        log.warning(
            "graph.kickoff_no_conversation_id",
            run_id=str(state.run_id),
            error=result.error,
            status_code=result.target_status_code,
        )
        await publish(
            kind="kickoff_failed",
            campaign_id=state.campaign_id,
            run_id=state.run_id,
            payload={
                "status_code": result.target_status_code,
                "latency_ms": result.target_latency_ms,
                "error": result.error or "no conversation_id returned",
            },
        )
    return state
