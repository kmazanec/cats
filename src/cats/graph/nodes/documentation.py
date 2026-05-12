"""Documentation node.

The actual persistence (Attack / AttackExecution / JudgeVerdict /
Finding / VulnerabilityReport rows) happens here — it's the last node
and we want it to write the full chain atomically per run.

When the judge verdict is `pass`, we also call the Documentation Agent
LLM to produce a Markdown vulnerability report. On `fail` / `partial`
no finding is promoted; the AttackExecution row records the attempt
but no Finding/Report is created.
"""

from __future__ import annotations

from cats.agents.documentation.writer import write_report
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.rubric_repo import ensure_rubric_version
from cats.db.repositories.run_repo import (
    mark_run_completed,
    record_execution,
    record_report,
    record_verdict,
    upsert_attack,
    upsert_finding,
)
from cats.graph.events import publish
from cats.graph.state import AgentCostEntry, CampaignState
from cats.llm.client import get_llm


async def run(state: CampaignState) -> CampaignState:
    category = state.selected_category or "injection"

    async with session_scope() as session:
        # Always-persist: the attack template + the execution row + the
        # judge verdict, regardless of pass/fail. Idempotent on
        # (category, signature) for the attack.
        attack_id = await upsert_attack(
            session,
            category=category,
            title=state.pending_attack_title,
            description=state.pending_attack_description,
            payload=state.pending_attack_payload,
            signature=state.pending_attack_signature,
            source="red_team" if not state.smoke_mode else "seed",
            run_id=state.run_id,
        )

        # Resolve the locked rubric version that the judge used (R2: v1).
        rubric_version_id = None
        if not state.last_verdict_is_deterministic and state.last_verdict in (
            "pass",
            "fail",
            "partial",
        ):
            rubric_version_id = await ensure_rubric_version(
                session, category=category, version="v1"
            )

        verdict_id = await record_verdict(
            session,
            verdict=state.last_verdict or "partial",
            is_deterministic=state.last_verdict_is_deterministic,
            rationale=state.last_verdict_rationale,
            evidence=state.last_verdict_evidence,
            judge_model=state.last_verdict_model or "deterministic",
            rubric_version_id=rubric_version_id,
        )
        state.last_verdict_id = verdict_id
        state.last_rubric_version_id = rubric_version_id

        # Sum per-agent costs for THIS execution's `model` / token counts.
        # When multiple LLM calls were involved (specialist + judge), the
        # AttackExecution row records the *total*; the per_agent_costs
        # list on state preserves the breakdown for the dashboard.
        #
        # Note: the doc-agent LLM call happens *after* this rollup (line
        # below, only when verdict='pass'). The execution row therefore
        # reflects the cost-to-judge; state.per_agent_costs will grow by
        # one more entry after the doc agent runs, and that entry is
        # tagged role='documentation' so the dashboard's per-role
        # rollup sees it. This is intentional: the AttackExecution row
        # is "what it cost to fire and judge this attack"; the doc
        # agent is a run-level overhead, not part of the attack itself.
        total_tokens_in = sum(c.tokens_in for c in state.per_agent_costs)
        total_tokens_out = sum(c.tokens_out for c in state.per_agent_costs)
        total_usd = sum(c.usd for c in state.per_agent_costs)
        primary_model = state.per_agent_costs[-1].model if state.per_agent_costs else "smoke"
        primary_role = state.per_agent_costs[-1].role if state.per_agent_costs else "smoke"

        execution_id = await record_execution(
            session,
            run_id=state.run_id,
            attack_id=attack_id,
            project_version_id=state.project_version_id,
            target_response=state.last_target_response,
            target_status_code=state.last_target_status_code,
            target_latency_ms=state.last_target_latency_ms,
            output_filter_verdict=state.output_filter_verdict,
            output_filter_reason=state.output_filter_reason,
            judge_verdict_id=verdict_id,
            model=primary_model,
            agent_role=primary_role,
            tokens_in=total_tokens_in,
            tokens_out=total_tokens_out,
            usd_estimate=total_usd,
            langsmith_trace_id=state.last_trace_id or None,
        )

        # Promote a Finding + write a Report on `pass` only.
        finding_id = None
        report_id = None
        if state.last_verdict == "pass":
            finding_id = await upsert_finding(
                session,
                run_id=state.run_id,
                category=category,
                signature=state.pending_attack_signature,
                title=state.pending_attack_title or f"[{category}] confirmed",
                severity="high",
                summary=state.last_verdict_rationale,
                atlas_technique_id="AML.T0051" if category == "injection" else None,
                owasp_llm_id="LLM01" if category == "injection" else None,
            )
            state.finding_id = finding_id

            # Doc agent LLM (skipped in smoke mode to keep it offline).
            if not state.smoke_mode:
                body, doc_llm = await write_report(
                    llm=get_llm(),
                    category=category,
                    technique=state.selected_technique,
                    attack_user_message=str(state.pending_attack_payload.get("user_message", "")),
                    target_response_text=state.last_target_text,
                    verdict=state.last_verdict,
                    rationale=state.last_verdict_rationale,
                )
                state.per_agent_costs.append(
                    AgentCostEntry(
                        role="documentation",
                        model=doc_llm.model,
                        tokens_in=doc_llm.tokens_in,
                        tokens_out=doc_llm.tokens_out,
                        usd=doc_llm.usd_estimate,
                    )
                )
                state.budget_consumed_usd += doc_llm.usd_estimate
            else:
                body = (
                    f"# [smoke] {state.pending_attack_title}\n\n"
                    "_Documentation Agent skipped in smoke mode._\n"
                )

            report_id = await record_report(
                session,
                run_id=state.run_id,
                finding_id=finding_id,
                title=state.pending_attack_title,
                body_markdown=body,
            )
            state.report_id = report_id

            await write_audit(
                session,
                actor="cats.platform",
                action="finding.promoted",
                target_kind="finding",
                target_id=finding_id,
                payload={
                    "category": category,
                    "verdict": state.last_verdict,
                    "execution_id": str(execution_id),
                    "report_id": str(report_id),
                },
                trace_id=state.last_trace_id or None,
            )

        await mark_run_completed(
            session,
            run_id=state.run_id,
            attacks_fired=state.attacks_fired,
            budget_consumed_usd=state.budget_consumed_usd,
        )

    # Live event for the dashboard.
    await publish(
        kind="finding_promoted" if finding_id else "run_completed",
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "verdict": state.last_verdict,
            "finding_id": str(finding_id) if finding_id else None,
            "report_id": str(report_id) if report_id else None,
            "budget_consumed_usd": round(state.budget_consumed_usd, 4),
            "per_agent_costs": [c.model_dump() for c in state.per_agent_costs],
        },
    )
    return state
