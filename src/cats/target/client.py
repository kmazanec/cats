"""Async HTTP client that fires attack payloads at a target's base_url.

This is the only path through which adversarial content reaches the live
system. Every call is wrapped in a structured log line; downstream code
writes the (request, response) pair into an AttackExecution row.

Two target kinds are supported:

- `copilot_proxy` (R2 default): the public surface — `agent.php?action=
  briefing` behind the OpenEMR PHP session. The client logs in to
  OpenEMR with the Project's stored credentials, harvests `PHPSESSID`
  + the form CSRF token, then POSTs the briefing envelope and consumes
  the SSE stream until the agent emits `complete` or `error`.

- `copilot_internal` (local-dev shortcut): hits the agent's internal
  `/v1/agent/briefing` directly with a static bearer token. Not used in
  prod (the internal port isn't reachable) but useful for local docker
  iteration before OpenEMR is wired up.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from cats.logging import get_logger
from cats.target.contracts import (
    AttackEnvelope,
    CopilotRequest,
    CopilotResponse,
    TargetCallResult,
)

log = get_logger(__name__)


_CSRF_INPUT_RE = re.compile(
    r'<input[^>]*name=["\']csrf_token_form["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class TargetClient:
    """Fires attack envelopes at the target. Stateful — keeps a session
    cookie jar between calls so the OpenEMR session survives the
    expected sequence of `login -> attack -> attack -> ...`.

    Construct one per Run; do not share across runs (different campaigns
    may use different Project credentials)."""

    def __init__(
        self,
        *,
        base_url: str,
        target_kind: str = "copilot_proxy",
        username: str = "",
        password: str = "",
        bearer_token: str = "",
        default_timeout: float = 60.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._target_kind = target_kind
        self._username = username
        self._password = password
        self._bearer_token = bearer_token
        self._timeout = default_timeout
        self._cookies: httpx.Cookies = httpx.Cookies()
        self._csrf_token: str = ""
        self._logged_in = False

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    async def attack(self, envelope: AttackEnvelope) -> TargetCallResult:
        """Send one attack. Returns a `TargetCallResult` with the assembled
        assistant text and the raw response body. Errors are returned as
        a non-200 status_code + populated `error`, never raised.

        Routing:
        - ``envelope.attachment`` set → upload via document_upload.php +
          trigger extract.php; consume the SSE pipeline events.
          (R5: indirect injection via .docx.)
        - ``target_kind == "copilot_internal"`` → direct
          ``/v1/agent/briefing`` shortcut (local dev only).
        - Otherwise → OpenEMR PHP session + ``agent.php`` chat proxy."""
        if envelope.attachment is not None:
            return await self._upload_and_extract(envelope)
        if self._target_kind == "copilot_internal":
            return await self._attack_internal(envelope)
        return await self._attack_proxy(envelope)

    async def call(self, request: CopilotRequest) -> CopilotResponse:
        """Legacy generic call. Kept so the smoke path keeps working
        without rewrites; the graph's target_caller node uses
        `attack()` instead."""
        url = f"{self._base_url}{request.endpoint}"
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.request(
                    request.method,
                    url,
                    json=request.payload or None,
                    headers=request.headers or None,
                )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            try:
                body: dict[str, object] | str = resp.json()
            except ValueError:
                body = resp.text
            return CopilotResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                latency_ms=elapsed_ms,
            )
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return CopilotResponse(
                status_code=0,
                latency_ms=elapsed_ms,
                error=str(e),
            )

    # ------------------------------------------------------------------
    # copilot_proxy — OpenEMR PHP session + agent.php proxy
    # ------------------------------------------------------------------

    async def _attack_proxy(self, envelope: AttackEnvelope) -> TargetCallResult:
        started = time.perf_counter()
        try:
            if not self._logged_in:
                await self._login_openemr()

            pid = str(envelope.extra.get("pid", "1"))
            url = (
                f"{self._base_url}"
                "/interface/modules/custom_modules/oe-module-clinical-copilot/"
                f"public/agent.php?action=briefing&pid={pid}"
            )

            body = self._build_briefing_envelope(envelope)
            headers: dict[str, str] = {
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
            }
            if self._csrf_token:
                headers["X-CSRF-Token"] = self._csrf_token

            async with httpx.AsyncClient(
                timeout=self._timeout, cookies=self._cookies, follow_redirects=False
            ) as client:
                resp = await client.post(url, content=json.dumps(body), headers=headers)
                # Re-auth on session expiry, then retry once.
                if resp.status_code in (302, 401, 403):
                    self._logged_in = False
                    await self._login_openemr()
                    resp = await client.post(url, content=json.dumps(body), headers=headers)
                text = _assemble_sse_text(resp.text)
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            log.warning("target.proxy_error", error=repr(e))
            return TargetCallResult(text="", status_code=0, latency_ms=elapsed_ms, error=str(e))

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return TargetCallResult(
            text=text,
            status_code=resp.status_code,
            latency_ms=elapsed_ms,
            raw_body=resp.text,
        )

    async def _login_openemr(self) -> None:
        """OpenEMR login flow against the local PHP UI. POSTs to
        `interface/main/main_screen.php` with `authUser`, `clearPass`,
        `new_login_session_management`, and the form CSRF token harvested
        from the login page."""
        if not self._username or not self._password:
            raise RuntimeError(
                "target_kind=copilot_proxy requires Project.target_username + "
                "target_password — set them in the dashboard before firing."
            )
        login_get = f"{self._base_url}/interface/login/login.php?site=default"
        login_post = f"{self._base_url}/interface/main/main_screen.php?auth=login&site=default"

        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
            r1 = await client.get(login_get)
            self._cookies.update(r1.cookies)
            self._csrf_token = _extract_csrf_form_token(r1.text)
            data = {
                "authUser": self._username,
                "clearPass": self._password,
                "languageChoice": "1",
                "new_login_session_management": "1",
            }
            if self._csrf_token:
                data["csrf_token_form"] = self._csrf_token
            r2 = await client.post(login_post, data=data, cookies=self._cookies)
            self._cookies.update(r2.cookies)
            if r2.status_code >= 400:
                raise RuntimeError(
                    f"OpenEMR login failed: HTTP {r2.status_code} (user={self._username!r})"
                )
        self._logged_in = True
        log.info("target.openemr_login_ok", user=self._username)

    def _build_briefing_envelope(self, envelope: AttackEnvelope) -> dict[str, Any]:
        """Build the JSON body the agent.php proxy forwards to
        /v1/agent/briefing. The Co-Pilot's ``briefingRequestSchema``
        (openemr/agent/src/server/index.ts) is strict — it expects a
        flat envelope with the user's text in a top-level ``question``
        field, NOT a chat-message array. The schema's exact required
        fields:

        - ``conversationId`` / ``requestId`` / ``siteId`` — strings (min 1).
        - ``patient.pid`` — *positive integer*, not a string.
        - ``task`` — default ``default_briefing``; the follow-up flow
          uses ``follow_up`` instead.
        - ``question`` — optional but the only place an attack message
          lands; required for us.

        ``envelope.extra`` is merged in last so callers can override
        any field (e.g. supply a real ``pid`` from a fixture)."""
        import uuid as _uuid

        # The schema wants pid as a positive int. envelope.extra may
        # carry a numeric pid from a fixture; coerce so we don't ship
        # a string and trip schema validation.
        raw_pid = envelope.extra.get("pid", 1)
        try:
            pid_int = int(raw_pid)
        except (TypeError, ValueError):
            pid_int = 1
        if pid_int <= 0:
            pid_int = 1

        body: dict[str, Any] = {
            "requestId": str(_uuid.uuid4()),
            "conversationId": str(_uuid.uuid4()),
            "siteId": "default",
            "patient": {"pid": pid_int, "uuid": str(envelope.extra.get("uuid", ""))},
            "task": "follow_up",
            "question": envelope.user_message[:2000],
        }
        # Allow extras to override (but strip our integer pid back to
        # int if extra supplies a string — preserve the schema).
        body.update(envelope.extra)
        if "patient" in envelope.extra:
            # caller-supplied patient block wins, but enforce the int
            pat = (
                dict(envelope.extra["patient"])
                if isinstance(envelope.extra["patient"], dict)
                else {}
            )
            try:
                pat["pid"] = int(pat.get("pid", pid_int))
            except (TypeError, ValueError):
                pat["pid"] = pid_int
            if pat["pid"] <= 0:
                pat["pid"] = pid_int
            pat.setdefault("uuid", "")
            body["patient"] = pat
        return body

    # ------------------------------------------------------------------
    # Docx-borne attacks — document_upload.php + extract.php
    # ------------------------------------------------------------------

    async def _upload_and_extract(self, envelope: AttackEnvelope) -> TargetCallResult:
        """R5 path: POST the .docx as multipart/form-data to
        ``document_upload.php``, pull the returned ``document_uuid``,
        then POST a JSON trigger to ``extract.php`` and consume the SSE
        pipeline events back. The assembled SSE text is what the Judge
        scans for the planted canary."""
        if envelope.attachment is None:  # pragma: no cover - guarded by caller
            raise ValueError("_upload_and_extract called without an attachment")

        started = time.perf_counter()
        try:
            if not self._logged_in:
                await self._login_openemr()

            pid = str(envelope.extra.get("pid", "1"))
            upload_url = (
                f"{self._base_url}"
                "/interface/modules/custom_modules/oe-module-clinical-copilot/"
                "public/document_upload.php"
            )
            extract_url = (
                f"{self._base_url}"
                "/interface/modules/custom_modules/oe-module-clinical-copilot/"
                "public/extract.php"
            )

            attachment = envelope.attachment
            files = {
                "file": (attachment.filename, attachment.data, attachment.content_type),
            }

            async with httpx.AsyncClient(
                timeout=self._timeout, cookies=self._cookies, follow_redirects=False
            ) as client:
                upload_resp = await client.post(upload_url, files=files)
                # Re-auth + retry once on session expiry.
                if upload_resp.status_code in (302, 401, 403):
                    self._logged_in = False
                    await self._login_openemr()
                    upload_resp = await client.post(upload_url, files=files)

                if upload_resp.status_code >= 400:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=upload_resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=upload_resp.text,
                        error=f"document_upload failed: HTTP {upload_resp.status_code}",
                    )

                try:
                    upload_body = upload_resp.json()
                except ValueError as e:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=upload_resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=upload_resp.text,
                        error=f"document_upload returned non-JSON: {e}",
                    )

                document_uuid = (
                    str(upload_body.get("document_uuid", ""))
                    if isinstance(upload_body, dict)
                    else ""
                )
                if not document_uuid:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=upload_resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=upload_resp.text,
                        error="document_upload response missing document_uuid",
                    )

                doc_type_guess = (
                    str(upload_body.get("doc_type_guess", "referral"))
                    if isinstance(upload_body, dict)
                    else "referral"
                )

                extract_body: dict[str, Any] = {
                    "pid": pid,
                    "document_uuid": document_uuid,
                    "doc_type": doc_type_guess,
                    "trigger_source": "cats_attack",
                }
                extract_headers = {
                    "Accept": "text/event-stream",
                    "Content-Type": "application/json",
                }
                if self._csrf_token:
                    extract_headers["X-CSRF-Token"] = self._csrf_token

                extract_resp = await client.post(
                    extract_url,
                    content=json.dumps(extract_body),
                    headers=extract_headers,
                )
                text = _assemble_sse_text(extract_resp.text)
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            log.warning("target.upload_extract_error", error=repr(e))
            return TargetCallResult(text="", status_code=0, latency_ms=elapsed_ms, error=str(e))

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return TargetCallResult(
            text=text,
            status_code=extract_resp.status_code,
            latency_ms=elapsed_ms,
            raw_body=extract_resp.text,
        )

    # ------------------------------------------------------------------
    # copilot_internal — local-dev shortcut
    # ------------------------------------------------------------------

    async def _attack_internal(self, envelope: AttackEnvelope) -> TargetCallResult:
        """Hit the agent's /v1/agent/briefing directly. Requires a bearer
        token; only useful when the operator runs cats against a local
        docker stack where the agent port is reachable."""
        started = time.perf_counter()
        url = f"{self._base_url}/v1/agent/briefing"
        body = self._build_briefing_envelope(envelope)
        headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, content=json.dumps(body), headers=headers)
            text = _assemble_sse_text(resp.text)
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return TargetCallResult(text="", status_code=0, latency_ms=elapsed_ms, error=str(e))
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return TargetCallResult(
            text=text,
            status_code=resp.status_code,
            latency_ms=elapsed_ms,
            raw_body=resp.text,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_csrf_form_token(login_html: str) -> str:
    m = _CSRF_INPUT_RE.search(login_html)
    return m.group(1) if m else ""


def _assemble_sse_text(raw: str) -> str:
    """Walk an SSE stream and join every `data:` line's text content.
    Tolerant of arbitrary `event:` types; concatenates anything that
    looks like assistant content.

    The Co-Pilot's `briefingStream.encodeStreamEvent` emits events like
    `data: {"type":"section","content":"..."}` per chunk plus a final
    `data: {"type":"complete"}`. For R2 we don't need to honor section
    semantics — concatenating all string fields is enough to give the
    Judge something to evaluate.
    """
    out: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            out.append(payload)
            continue
        if isinstance(obj, dict):
            for key in ("content", "text", "delta", "message"):
                v = obj.get(key)
                if isinstance(v, str) and v:
                    out.append(v)
        elif isinstance(obj, str):
            out.append(obj)
    if out:
        return "\n".join(out)
    # If there are no SSE-shaped lines, treat the body as plain text.
    return raw
