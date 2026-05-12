"""Output Filter node.

Stands between the Red Team / Mutator and the live target. Regex scan
catches PII shapes (SSN, MRN, credit-card), executable-payload
signatures, and zero-width-character smuggling. When verdict is
`dangerous` the graph short-circuits to documentation (the conditional
edge in `build.py`) — the live target never sees the payload.

LLM-classifier promotion (`attack_payload` -> `dangerous`) is deferred.
"""

from __future__ import annotations

import json

from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.output_filter.regex_scanner import scan_text


async def run(state: CampaignState) -> CampaignState:
    payload_str = json.dumps(state.pending_attack_payload, ensure_ascii=False)
    result = scan_text(payload_str)
    state.output_filter_verdict = result.verdict
    state.output_filter_reason = result.reason

    if result.verdict != "safe":
        await publish(
            kind="campaign_halted",
            campaign_id=state.campaign_id,
            run_id=state.run_id,
            payload={
                "stage": "output_filter",
                "verdict": result.verdict,
                "reason": result.reason,
            },
        )
    return state
