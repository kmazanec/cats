"""Documentation worker process.

Consumes ``VerdictRendered(pass | fail | error)`` from the Judge. On
``pass``, writes a ``Finding`` + ``VulnerabilityReport`` and emits
``FindingPromoted``. On ``fail``/``error``, nothing to promote — just
marks the run completed and acks the message; the platform's audit
trail still has the AttackExecution + JudgeVerdict rows.

After handling any verdict, the worker checks whether the campaign is
now in a terminal state (all runs reached completed/failed/halted).
If yes, it triggers the campaign-report writer once (idempotent via
the unique constraint on ``campaign_reports.campaign_id``). The
writer runs the Documentation LLM in a tool loop to gather facts +
render visual artifacts, then persists the markdown + artifact
metadata.

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
from cats.db.repositories.run_repo import (
    mark_run_completed,
    record_report,
    upsert_finding,
)
from cats.db.schema import attack_executions, attacks, runs
from cats.graph.events import publish
from cats.llm.client import get_llm
from cats.messaging import (
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
        if message.kind is not MessageKind.VERDICT_RENDERED:
            self._log.error(
                "documentation.unexpected_kind",
                kind=message.kind.value,
                message_id=str(message.message_id),
            )
            return
        payload = VerdictRenderedPayload.model_validate(message.payload_json)
        if payload.verdict == "partial":
            # partial verdicts route to red_team — if one landed here
            # it's a routing bug; drop it noisily.
            self._log.warning(
                "documentation.partial_misroute",
                attack_id=str(payload.attack_id),
            )
            return
        await self._handle_verdict(session, payload, trace_id=message.trace_id)
        # After the per-run bookkeeping for this verdict, check whether
        # the campaign as a whole is now terminal. If yes, fire the
        # rollup report. Skipped on partial (routes back to red_team)
        # because the campaign hasn't actually finished yet — the
        # variant loop is still in flight.
        await self._maybe_generate_campaign_report(
            session,
            campaign_id=payload.campaign_id,
            trace_id=message.trace_id,
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

    async def _maybe_generate_campaign_report(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        trace_id: str,
    ) -> None:
        """If every run in the campaign is in a terminal state, fire
        the campaign-report writer. Idempotent on ``campaign_id`` via
        ``campaign_reports.campaign_id`` UNIQUE: a re-arriving verdict
        for an already-reported campaign just re-stamps the row
        (UPSERT in ``upsert_pending_report``). Run inside the message
        handler's session so the LLM tool loop sees the same write
        scope; the bus's per-message visibility timeout (60s) bounds
        the worst-case stall."""
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
        # Reserve / re-stamp the row. If another worker raced us to this
        # point the UPSERT is harmless — the writer just regenerates.
        await upsert_pending_report(session, campaign_id=campaign_id)
        await session.commit()

        self._log.info(
            "campaign_report.generating",
            campaign_id=str(campaign_id),
            runs=total,
        )
        try:
            result = await write_campaign_report(
                llm=get_llm(),
                session=session,
                campaign_id=campaign_id,
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
                payload={"error": repr(exc)},
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
