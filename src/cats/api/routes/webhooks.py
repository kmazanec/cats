"""R8 deploy webhook (per-project secret).

``POST /webhooks/deploy/{project_id}`` accepts an HMAC-signed signal
from the named project's CI when a new version of the target has been
deployed. The route looks up the project, decrypts its per-project
``deploy_webhook_secret``, verifies the HMAC against the raw body,
and enqueues a regression sweep against that project.

Why per-project (R8 followup, 2026-05-13): the original R8 ship used
a single global ``settings.deploy_webhook_secret``, which would cap
the platform at one project's CI ever being able to authenticate. The
secret lives on the project row now (Fernet-encrypted), matching the
shape of every other per-project credential.

Auth model:

- URL path carries the project id — the server uses it to look up the
  correct secret BEFORE parsing the body. Verifies signature, then
  parses.
- Header ``X-CATS-Signature: sha256=<hex>``.
- HMAC-SHA256 over the **raw request body**.
- Constant-time comparison via :func:`hmac.compare_digest`.
- Project not found → 404.
- Project found but no secret configured → 503 (project hasn't opted
  in to webhook-driven sweeps).
- Missing / malformed signature → 401.
- Audit-logged at every state; failed attempts are visible so a
  misconfigured CI doesn't fail silently.

Request body shape::

    {
      "version_tag": "<string>",    // optional; surfaced in the UI
      "deployed_at": "<iso8601>"    // optional; informational
    }
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import select

from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.schema import projects
from cats.security.crypto import decrypt
from cats.workers.regression_sweep import schedule_sweep_in_background

router = APIRouter()


def expected_signature(body: bytes, secret: str) -> str:
    """Public so tests can construct a valid header without copying the
    computation. Keep in sync with the verification path below."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


async def _resolve_project_secret(project_id: UUID) -> str | None:
    """Look up the project's encrypted webhook secret and decrypt it.
    Returns None when the project exists but has no secret configured,
    or raises HTTPException(404) when the project doesn't exist."""
    async with session_scope() as session:
        row = (
            await session.execute(
                select(projects.c.deploy_webhook_secret_encrypted).where(
                    projects.c.id == project_id
                )
            )
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="project not found")
    encrypted = row.deploy_webhook_secret_encrypted
    if not encrypted:
        return None
    return decrypt(encrypted)


@router.post("/deploy/{project_id}")
async def deploy_webhook(
    project_id: UUID,
    request: Request,
    x_cats_signature: str | None = Header(default=None, alias="X-CATS-Signature"),
) -> dict[str, Any]:
    raw_body = await request.body()

    try:
        secret = await _resolve_project_secret(project_id)
    except HTTPException:
        # Audit before bubbling — a misconfigured CI hitting an unknown
        # project should be visible, not just a 404 in HTTP logs.
        async with session_scope() as session:
            await write_audit(
                session,
                actor="cats.platform.webhook",
                action="regression.webhook.unknown_project",
                target_kind="project",
                target_id=project_id,
                payload={"reason": "project_id not in projects table"},
            )
        raise

    # 503: the project exists but its owner hasn't configured a secret.
    # Refuse to accept ANY webhook traffic in this state — accepting
    # unsigned webhooks would turn the platform into an attacker-driven
    # sweep amplifier. 503 (not 401) signals to the CI that the
    # receiver isn't ready, not that the credentials are wrong.
    if not secret:
        async with session_scope() as session:
            await write_audit(
                session,
                actor="cats.platform.webhook",
                action="regression.webhook.unconfigured",
                target_kind="project",
                target_id=project_id,
                payload={"reason": "project has no deploy_webhook_secret"},
            )
        raise HTTPException(
            status_code=503,
            detail="deploy webhook not configured for this project",
        )

    if not x_cats_signature or not hmac.compare_digest(
        x_cats_signature, expected_signature(raw_body, secret)
    ):
        async with session_scope() as session:
            await write_audit(
                session,
                actor="cats.platform.webhook",
                action="regression.webhook.rejected",
                target_kind="project",
                target_id=project_id,
                payload={"reason": "signature_invalid_or_missing"},
            )
        raise HTTPException(status_code=401, detail="invalid signature")

    # Parse body AFTER signature verification — never trust unsigned
    # JSON. Body is optional; an empty body verifies fine if the
    # signature matches sha256("").
    body: dict[str, Any] = {}
    if raw_body:
        try:
            parsed = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"body not JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        body = parsed

    version_tag = str(body.get("version_tag") or "")[:120]

    async with session_scope() as session:
        await write_audit(
            session,
            actor="cats.platform.webhook",
            action="regression.webhook.accepted",
            target_kind="project",
            target_id=project_id,
            payload={"version_tag": version_tag, "body": body},
        )

    sweep_id = schedule_sweep_in_background(
        project_id=project_id,
        version_tag=version_tag,
        triggered_by="deploy_webhook",
    )
    return {
        "status": "queued",
        "project_id": str(project_id),
        "version_tag": version_tag,
        "sweep_id": str(sweep_id),
    }
