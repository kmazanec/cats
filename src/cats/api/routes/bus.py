"""Operator-facing /bus dashboard.

Surfaces three views of the message bus that the four agents communicate
across (see ``cats.messaging.bus``):

  * Per-agent inbox depth (a quick "are workers keeping up?" signal).
  * Recent in-flight messages (last 100) with a derived status column.
  * Dead-letter queue with a per-row Re-queue button (CSRF-required).

The HTMX panels poll every 3 seconds; we deliberately do *not* wire a
Redis pub/sub channel here. Live pub/sub is a roadmap nice-to-have but
adds a Redis-connection lifecycle that doesn't pay off for an internal
ops view that already gets a 3s refresh.

Auth: the page itself is viewable by any signed-in user (mirrors
``/audit``); the re-queue POST is gated to ``operator`` and CSRF-checked.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from cats.api.auth import Principal, require_role, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.logging import get_logger
from cats.messaging.bus import Bus
from cats.security.csrf import require_csrf

log = get_logger(__name__)
router = APIRouter()

# Agents that consume from the bus (i.e. legal ``to_agent`` values, minus
# 'operator'/'system' which aren't worker inboxes in the usual sense).
INBOX_AGENTS: tuple[str, ...] = (
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
)

# Visual cap on the inbox-depth bar so a deeply backlogged inbox doesn't
# blow the panel layout. The numeric count is always shown verbatim.
INBOX_BAR_CAP = 25

INFLIGHT_LIMIT = 100


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "bus",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
    }


@router.get("")
async def bus_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    """Full page render. The three panels load their bodies via HTMX
    immediately and poll every 3s thereafter."""
    ctx = _chrome_ctx(principal)
    ctx["agents"] = INBOX_AGENTS
    return templates.TemplateResponse(request, "bus.html", ctx)


@router.get("/inbox-depth")
async def inbox_depth_partial(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTMX partial: bar-per-agent inbox depth."""
    _ = principal
    bus = Bus()
    rows: list[dict[str, Any]] = []
    async with session_scope() as session:
        for agent in INBOX_AGENTS:
            depth = await bus.inbox_depth(session, agent)
            pct = min(100, int((depth / INBOX_BAR_CAP) * 100)) if depth else 0
            rows.append({"agent": agent, "depth": depth, "pct": pct})
    return templates.TemplateResponse(
        request,
        "_bus_inbox_depth.html",
        {"rows": rows, "cap": INBOX_BAR_CAP},
    )


@router.get("/dead-letters")
async def dead_letters_partial(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTMX partial: table of unrequeued dead letters."""
    async with session_scope() as session:
        result = await session.execute(
            text(
                """
                SELECT id, message_id, to_agent, kind, last_error,
                       dead_lettered_at
                FROM agent_dead_letters
                WHERE requeued_at IS NULL
                ORDER BY dead_lettered_at DESC
                LIMIT 200
                """
            )
        )
        rows = [
            {
                "id": r.id,
                "message_id": r.message_id,
                "to_agent": r.to_agent,
                "kind": r.kind,
                "last_error": r.last_error,
                "dead_lettered_at": r.dead_lettered_at,
            }
            for r in result.all()
        ]
    return templates.TemplateResponse(
        request,
        "_bus_dead_letters.html",
        {"rows": rows, "request": request, "principal": principal},
    )


@router.get("/inflight")
async def inflight_partial(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTMX partial: recent messages (newest first) with a derived status.

    Status semantics:

      * ``consumed`` — ``consumed_at`` is set.
      * ``dead_lettered`` — an ``agent_dead_letters`` row exists with
        ``requeued_at IS NULL``.
      * ``claimed`` — a worker has it (``visible_after`` is in the
        future, ``consumed_at`` still NULL).
      * ``queued`` — visible and waiting for a claim.
    """
    _ = principal
    async with session_scope() as session:
        result = await session.execute(
            text(
                """
                SELECT
                  am.id,
                  am.kind,
                  am.from_agent,
                  am.to_agent,
                  am.created_at,
                  am.visible_after,
                  am.consumed_at,
                  am.attempts,
                  EXTRACT(EPOCH FROM (now() - am.created_at))::bigint AS age_seconds,
                  EXISTS (
                      SELECT 1 FROM agent_dead_letters dl
                      WHERE dl.message_id = am.id
                        AND dl.requeued_at IS NULL
                  ) AS is_dead_lettered
                FROM agent_messages am
                ORDER BY am.created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": INFLIGHT_LIMIT},
        )
        rows: list[dict[str, Any]] = []
        for r in result.all():
            if r.consumed_at is not None:
                status = "consumed"
            elif r.is_dead_lettered:
                status = "dead_lettered"
            elif r.visible_after is not None and r.attempts > 0:
                # A row whose attempts > 0 and which is not yet consumed
                # is either claimed-and-running (visible_after in future)
                # or backed-off after a nack. Both render as 'claimed'
                # for the dashboard's purposes; the operator gets the
                # attempts count alongside to disambiguate.
                status = "claimed"
            else:
                status = "queued"
            rows.append(
                {
                    "id": r.id,
                    "kind": r.kind,
                    "from_agent": r.from_agent,
                    "to_agent": r.to_agent,
                    "age_seconds": int(r.age_seconds or 0),
                    "attempts": r.attempts,
                    "status": status,
                }
            )
    return templates.TemplateResponse(
        request,
        "_bus_inflight.html",
        {"rows": rows, "limit": INFLIGHT_LIMIT},
    )


@router.post(
    "/dead-letters/{dead_letter_id}/requeue",
    dependencies=[Depends(require_csrf)],
)
async def requeue_dead_letter(
    request: Request,
    dead_letter_id: UUID,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """Operator-triggered re-queue. Resets the message's attempts,
    NOTIFY-wakes the destination agent, and writes an audit-log row."""
    _ = request
    bus = Bus()
    async with session_scope() as session:
        message_id = await bus.requeue_dead_letter(
            session,
            dead_letter_id,
            operator=principal.email,
        )
        if message_id is None:
            raise HTTPException(
                status_code=404,
                detail="dead letter not found or already requeued",
            )
        await write_audit(
            session,
            actor=principal.email,
            action="bus.dead_letter.requeued",
            target_kind="agent_message",
            target_id=message_id,
            payload={
                "dead_letter_id": str(dead_letter_id),
                "operator": principal.email,
            },
        )
    log.info(
        "bus.dead_letter.requeued",
        dead_letter_id=str(dead_letter_id),
        message_id=str(message_id),
        operator=principal.email,
    )
    return RedirectResponse(url="/bus", status_code=303)
