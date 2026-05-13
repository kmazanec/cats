"""R8 deploy webhook.

``POST /webhooks/deploy`` accepts an HMAC-signed signal from the
Co-Pilot CI when a new version of the target has been deployed. On a
valid signature, the route enqueues a regression sweep against the
named project and returns ``202 Accepted`` semantics (we return 200
with status=queued for FastAPI ergonomics, but the work is async).
The sweep runs in the background and updates each RegressionCase's
verdict as it completes.

Auth model:

- Header ``X-CATS-Signature: sha256=<hex>``.
- HMAC-SHA256 over the **raw request body** using
  ``settings.deploy_webhook_secret``.
- Constant-time comparison via :func:`hmac.compare_digest`.
- Missing secret → 503 (the platform owner has not opted into
  webhook-driven sweeps).
- Missing / malformed signature → 401.
- Audit-logged either way; failed attempts are visible to the
  operator so a misconfigured CI doesn't fail silently.

Request body shape::

    {
      "project_id": "<uuid>",       // required
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

from cats.config import get_settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.workers.regression_sweep import schedule_sweep_in_background

router = APIRouter()


def expected_signature(body: bytes, secret: str) -> str:
    """Public so tests can construct a valid header without copying the
    computation. Keep in sync with the verification path below."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@router.post("/deploy")
async def deploy_webhook(
    request: Request,
    x_cats_signature: str | None = Header(default=None, alias="X-CATS-Signature"),
) -> dict[str, Any]:
    raw_body = await request.body()
    secret = get_settings().deploy_webhook_secret

    # 503: the platform owner has not configured a secret. Refuse to
    # accept ANY webhook traffic in this state — accepting unsigned
    # webhooks would turn the platform into an attacker-driven sweep
    # amplifier. The status is 503 rather than 401 to make it clear
    # to a misconfigured CI that the receiver isn't ready, not that
    # the credentials are wrong.
    if not secret:
        async with session_scope() as session:
            await write_audit(
                session,
                actor="cats.platform.webhook",
                action="regression.webhook.unconfigured",
                target_kind="webhook",
                target_id=None,
                payload={"reason": "deploy_webhook_secret is empty"},
            )
        raise HTTPException(
            status_code=503,
            detail="deploy webhook is not configured on this CATS instance",
        )

    if not x_cats_signature or not hmac.compare_digest(
        x_cats_signature, expected_signature(raw_body, secret)
    ):
        async with session_scope() as session:
            await write_audit(
                session,
                actor="cats.platform.webhook",
                action="regression.webhook.rejected",
                target_kind="webhook",
                target_id=None,
                payload={"reason": "signature_invalid_or_missing"},
            )
        raise HTTPException(status_code=401, detail="invalid signature")

    # Parse body AFTER signature verification — never trust unsigned
    # JSON. Failure modes (truncated body, non-JSON, missing fields)
    # all surface as 400 with an audit entry.
    try:
        body = json.loads(raw_body or b"{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"body not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    project_id_str = str(body.get("project_id") or "")
    if not project_id_str:
        raise HTTPException(status_code=400, detail="missing project_id")
    try:
        project_id = UUID(project_id_str)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"project_id not a uuid: {exc}") from exc

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
