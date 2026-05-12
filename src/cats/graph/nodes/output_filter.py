"""Output filter node. Regex scan first; LLM classifier on inconclusive.
Marks state with the verdict so downstream knows whether to send."""

from __future__ import annotations

import json

from cats.graph.state import CampaignState
from cats.output_filter.regex_scanner import scan_text


async def run(state: CampaignState) -> CampaignState:
    payload_str = json.dumps(state.pending_attack_payload, ensure_ascii=False)
    result = scan_text(payload_str)
    state.output_filter_verdict = result.verdict
    state.output_filter_reason = result.reason
    return state
