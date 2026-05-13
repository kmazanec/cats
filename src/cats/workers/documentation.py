"""Documentation worker process.

Consumes ``VerdictRendered(pass | fail)`` from the Judge. On ``pass``,
writes a ``Finding`` + ``VulnerabilityReport`` and emits
``FindingPromoted``. On ``fail``, nothing to promote — just acks the
message and moves on; the platform's audit trail still has the
AttackExecution + JudgeVerdict rows from the prior workers.

Critical-severity findings carry ``awaiting_approval=True`` (R9 wires
the actual gate; R4 just records the row in ``documentation_drafts``).
"""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.documentation.writer import write_report
from cats.categories import taxonomy
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.run_repo import (
    mark_run_completed,
    record_report,
    upsert_finding,
)
from cats.db.schema import attack_executions, attacks
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


def main() -> None:
    """``uv run python -m cats.workers.documentation``"""
    asyncio.run(DocumentationWorker().run())


if __name__ == "__main__":
    main()


# unused-import guard so mypy doesn't grump
_ = (UUID, cast)
