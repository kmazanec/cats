"""Documentation worker process.

Consumes two message kinds:

1. ``VerdictRendered(pass | fail | error)`` from the Judge. On
   ``pass``, writes a ``Finding`` + ``VulnerabilityReport`` and emits
   ``FindingPromoted``. On ``fail``/``error``, marks the run
   completed; the platform's audit trail still has the
   AttackExecution + JudgeVerdict rows. After handling the verdict,
   if every run in the campaign is now terminal the worker emits a
   ``CAMPAIGN_REPORT_REQUESTED`` envelope so the rollup report
   generation happens asynchronously instead of blocking the
   verdict-handler latency.

2. ``CampaignReportRequested`` — runs the campaign-report writer's
   LLM tool loop, persists the markdown + artifacts via
   ``campaign_report_repo``, and publishes a
   ``campaign_report_generated`` SSE event so the UI can swap from
   the "generating" indicator to the rendered report without a
   page reload. The handler calls ``self.touch_claim`` between LLM
   turns so a slow tool loop doesn't trigger a false redelivery.

Run multiple replicas in parallel — the bus's ``FOR UPDATE SKIP
LOCKED`` guarantees one consumer per message, and the two workloads
share an inbox so per-attack findings and per-campaign rollups
balance across the pool.

Critical-severity findings carry ``awaiting_approval=True`` (R9 wires
the actual gate; R4 just records the row in ``documentation_drafts``).
"""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.documentation.campaign_writer import write_campaign_report
from cats.agents.documentation.writer import write_report
from cats.categories import taxonomy
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.campaign_report_repo import (
    mark_report_completed,
    mark_report_failed,
    upsert_pending_report,
)
from cats.db.repositories.regression_repo import ensure_regression_case
from cats.db.repositories.run_repo import (
    mark_run_completed,
    record_report,
    upsert_finding,
)
from cats.db.schema import attack_executions, attacks, runs
from cats.graph.events import publish
from cats.llm.client import get_llm
from cats.messaging import (
    CampaignReportRequestedPayload,
    ClaimedMessage,
    Envelope,
    FindingPromotedPayload,
    MessageKind,
    VerdictRenderedPayload,
    Worker,
)


class DocumentationWorker(Worker):
    """The Documentation agent's worker process."""

    agent_name = "documentation"
    visibility_timeout_seconds = 60

    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        if message.kind is MessageKind.VERDICT_RENDERED:
            payload = VerdictRenderedPayload.model_validate(message.payload_json)
            if payload.verdict == "partial":
                # partial verdicts route to red_team — if one landed
                # here it's a routing bug; drop it noisily.
                self._log.warning(
                    "documentation.partial_misroute",
                    attack_id=str(payload.attack_id),
                )
                return
            await self._handle_verdict(session, payload, trace_id=message.trace_id)
            # After the per-run bookkeeping for this verdict, check
            # whether the campaign as a whole is now terminal. If yes,
            # enqueue a CAMPAIGN_REPORT_REQUESTED envelope — the rollup
            # writer runs asynchronously so a slow LLM tool loop
            # doesn't head-of-line block the verdict-handler latency.
            await self._maybe_enqueue_campaign_report(
                session,
                campaign_id=payload.campaign_id,
                trace_id=message.trace_id,
            )
            return
        if message.kind is MessageKind.CAMPAIGN_REPORT_REQUESTED:
            payload_r = CampaignReportRequestedPayload.model_validate(message.payload_json)
            await self._handle_campaign_report(
                session,
                message_id=message.message_id,
                payload=payload_r,
                trace_id=message.trace_id,
            )
            return
        self._log.error(
            "documentation.unexpected_kind",
            kind=message.kind.value,
            message_id=str(message.message_id),
        )

    async def _handle_verdict(
        self,
        session: AsyncSession,
        payload: VerdictRenderedPayload,
        *,
        trace_id: str,
    ) -> None:
        # Look up the attack template + execution for the report body.
        row = (
            await session.execute(
                select(
                    attacks.c.category,
                    attacks.c.title,
                    attacks.c.signature,
                    attacks.c.payload,
                    attack_executions.c.target_response,
                )
                .select_from(
                    attack_executions.join(attacks, attacks.c.id == attack_executions.c.attack_id)
                )
                .where(attack_executions.c.id == payload.attack_execution_id)
            )
        ).first()
        if row is None:
            self._log.warning(
                "documentation.no_attack",
                attack_execution_id=str(payload.attack_execution_id),
            )
            return
        category = row.category
        technique = row.payload.get("technique", "") if isinstance(row.payload, dict) else ""
        user_message = row.payload.get("user_message", "") if isinstance(row.payload, dict) else ""
        response_text = ""
        if isinstance(row.target_response, dict):
            response_text = str(row.target_response.get("text", ""))

        if payload.verdict != "pass":
            # Fail: mark the run completed and move on.
            await mark_run_completed(
                session,
                run_id=payload.run_id,
                attacks_fired=1,
                budget_consumed_usd=0.0,
            )
            await publish(
                kind="run_completed",
                campaign_id=payload.campaign_id,
                run_id=payload.run_id,
                payload={"verdict": payload.verdict, "finding_id": None},
            )
            return

        # Pass: write the Finding + Report + audit + emit FindingPromoted.
        label = taxonomy.lookup(category, technique)
        finding_id = await upsert_finding(
            session,
            run_id=payload.run_id,
            category=category,
            signature=row.signature,
            title=row.title or f"[{category}] confirmed",
            severity="high",
            summary=payload.rationale,
            atlas_technique_id=label.atlas_technique_id,
            owasp_llm_id=label.owasp_llm_id,
        )
        # R8 — auto-promote confirmed findings into RegressionCases so the
        # deploy-time sweep has something to re-run. Pins the rubric
        # version that produced the verdict so the bar doesn't drift if
        # the rubric is later bumped.
        regression_case_id = await ensure_regression_case(
            session,
            source_finding_id=finding_id,
            canonical_attack_id=payload.attack_id,
            locked_rubric_version_id=payload.rubric_version_id,
        )
        body, _llm = await write_report(
            llm=get_llm(),
            category=category,
            technique=technique,
            attack_user_message=user_message,
            target_response_text=response_text,
            verdict=payload.verdict,
            rationale=payload.rationale,
        )
        report_id = await record_report(
            session,
            run_id=payload.run_id,
            finding_id=finding_id,
            title=row.title or f"[{category}] confirmed",
            body_markdown=body,
        )

        # documentation_drafts row tracks the awaiting_approval flag
        # for the R9 critical-severity gate. Severity is 'high' here so
        # awaiting_approval stays False; R9 flips it when severity=='critical'.
        await session.execute(
            text(
                """
                INSERT INTO documentation_drafts
                    (finding_id, status, awaiting_approval, updated_at)
                VALUES (:fid, 'published', false, now())
                ON CONFLICT (finding_id) DO UPDATE
                SET status = EXCLUDED.status, updated_at = now()
                """
            ),
            {"fid": finding_id},
        )

        await write_audit(
            session,
            actor="cats.platform.documentation",
            action="finding.promoted",
            target_kind="finding",
            target_id=finding_id,
            payload={
                "category": category,
                "technique": technique,
                "regression_case_id": str(regression_case_id),
                "verdict": payload.verdict,
                "execution_id": str(payload.attack_execution_id),
                "report_id": str(report_id),
            },
            trace_id=trace_id or None,
        )
        await mark_run_completed(
            session,
            run_id=payload.run_id,
            attacks_fired=1,
            budget_consumed_usd=0.0,
        )

        envelope = Envelope[FindingPromotedPayload](
            kind=MessageKind.FINDING_PROMOTED,
            from_agent="documentation",
            to_agent="system",
            payload=FindingPromotedPayload(
                campaign_id=payload.campaign_id,
                run_id=payload.run_id,
                finding_id=finding_id,
                report_id=report_id,
                severity="high",
                atlas_technique_id=label.atlas_technique_id,
                owasp_llm_id=label.owasp_llm_id,
                awaiting_approval=False,
            ),
            trace_id=trace_id,
            campaign_id=payload.campaign_id,
            idempotency_key=f"documentation:finding:{finding_id}",
        )
        await self._bus.emit(session, envelope)
        await publish(
            kind="finding_promoted",
            campaign_id=payload.campaign_id,
            run_id=payload.run_id,
            payload={
                "finding_id": str(finding_id),
                "report_id": str(report_id),
                "severity": "high",
            },
        )
        await publish(
            kind="run_completed",
            campaign_id=payload.campaign_id,
            run_id=payload.run_id,
            payload={"verdict": "pass", "finding_id": str(finding_id)},
        )

    async def _maybe_enqueue_campaign_report(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        trace_id: str,
    ) -> None:
        """If every run in the campaign is in a terminal state, emit a
        ``CAMPAIGN_REPORT_REQUESTED`` envelope. The writer runs
        asynchronously in another claim cycle so a slow LLM tool loop
        doesn't head-of-line block verdict handling.

        Idempotent: the envelope's ``idempotency_key`` is
        ``documentation:campaign_report:{campaign_id}:auto`` so
        re-arriving verdicts for an already-reported campaign collapse
        at insert time. The operator can still trigger a fresh
        regeneration via POST ``/campaigns/{id}/report`` — that path
        uses a different idempotency key with a uuid suffix."""
        row = (
            await session.execute(
                select(
                    func.count(runs.c.id).label("total"),
                    func.count(runs.c.id)
                    .filter(runs.c.status.in_(("completed", "failed", "halted")))
                    .label("terminal"),
                ).where(runs.c.campaign_id == campaign_id)
            )
        ).first()
        if row is None:
            return
        total = int(row.total or 0)
        terminal = int(row.terminal or 0)
        if total == 0 or terminal < total:
            self._log.debug(
                "campaign_report.not_yet_terminal",
                campaign_id=str(campaign_id),
                terminal=terminal,
                total=total,
            )
            return
        envelope = Envelope[CampaignReportRequestedPayload](
            kind=MessageKind.CAMPAIGN_REPORT_REQUESTED,
            from_agent="documentation",
            to_agent="documentation",
            payload=CampaignReportRequestedPayload(
                campaign_id=campaign_id,
                reason="auto_terminal",
            ),
            trace_id=trace_id,
            campaign_id=campaign_id,
            idempotency_key=f"documentation:campaign_report:{campaign_id}:auto",
        )
        new_id = await self._bus.emit(session, envelope)
        if new_id is None:
            self._log.debug(
                "campaign_report.auto_already_enqueued",
                campaign_id=str(campaign_id),
            )
        else:
            self._log.info(
                "campaign_report.auto_enqueued",
                campaign_id=str(campaign_id),
                runs=total,
            )

    async def _handle_campaign_report(
        self,
        session: AsyncSession,
        *,
        message_id: UUID,
        payload: CampaignReportRequestedPayload,
        trace_id: str,
    ) -> None:
        """Run the campaign-report writer. Reserves the row in
        ``generating`` status up front so the UI shows progress
        immediately; the LLM tool loop calls ``self.touch_claim``
        between turns so a slow loop doesn't trigger a false
        redelivery. On any exception the row flips to ``failed`` and
        the message acks (no point retrying — the writer will hit the
        same problem). Operators retry manually via the POST route."""
        campaign_id = payload.campaign_id
        await upsert_pending_report(session, campaign_id=campaign_id)
        # Commit the pending status so the operator's polling UI flips
        # right away. The writer's own work happens on the same
        # session afterward.
        await session.commit()

        self._log.info(
            "campaign_report.generating",
            campaign_id=str(campaign_id),
            reason=payload.reason,
        )

        async def _keep_alive(turn: int) -> bool:
            # Push the claim out by the worker's visibility timeout on
            # each LLM turn. A False return aborts the writer — the
            # handler then commits ``failed`` and acks the message.
            ok = await self.touch_claim(message_id)
            if not ok:
                self._log.warning(
                    "campaign_report.claim_lost",
                    campaign_id=str(campaign_id),
                    turn=turn,
                )
            return ok

        try:
            result = await write_campaign_report(
                llm=get_llm(),
                session=session,
                campaign_id=campaign_id,
                on_turn_start=_keep_alive,
            )
        except Exception as exc:
            self._log.exception(
                "campaign_report.writer_failed",
                campaign_id=str(campaign_id),
            )
            await mark_report_failed(
                session,
                campaign_id=campaign_id,
                reason=f"{type(exc).__name__}: {exc}",
            )
            await write_audit(
                session,
                actor="cats.platform.documentation",
                action="campaign_report.failed",
                target_kind="campaign",
                target_id=campaign_id,
                payload={"error": repr(exc), "reason": payload.reason},
                trace_id=trace_id or None,
            )
            return
        await mark_report_completed(
            session,
            campaign_id=campaign_id,
            body_markdown=result.body_markdown,
            artifacts=result.artifacts,
            model=result.model,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            usd_estimate=result.usd_estimate,
            tool_transcript=result.tool_transcript,
        )
        await write_audit(
            session,
            actor="cats.platform.documentation",
            action="campaign_report.generated",
            target_kind="campaign",
            target_id=campaign_id,
            payload={
                "artifacts": len(result.artifacts),
                "model": result.model,
                "tokens_in": result.tokens_in,
                "tokens_out": result.tokens_out,
                "usd_estimate": result.usd_estimate,
                "used_fallback": result.used_fallback,
                "reason": payload.reason,
            },
            trace_id=trace_id or None,
        )
        await publish(
            kind="campaign_report_generated",
            campaign_id=campaign_id,
            run_id=None,
            payload={
                "artifacts": len(result.artifacts),
                "used_fallback": result.used_fallback,
            },
        )


def main() -> None:
    """``uv run python -m cats.workers.documentation``"""
    asyncio.run(DocumentationWorker().run())


if __name__ == "__main__":
    main()


# unused-import guard so mypy doesn't grump
_ = (UUID, cast)
