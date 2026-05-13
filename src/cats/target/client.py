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
                # agent.php sometimes returns error SSEs on 4xx (e.g.
                # `event: error\ndata: {"type":"error","code":"invalid_envelope"}`).
                # The Judge sees the raw SSE either way (we hand it the
                # body verbatim), but conflating HTTP-error responses
                # with successful replies muddies the stream_shape
                # signal — mark 4xx explicitly so downstream verdict
                # logic can short-circuit on `target_rejected`.
                if resp.status_code >= 400:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=resp.text,
                        error=(f"agent.php failed: HTTP {resp.status_code} — {resp.text[:200]}"),
                    )
                # OpenEMR's proxy stamps SSE headers before checking the
                # upstream agent's auth. If the agent rejects with 401
                # the body is a bare ``{"error":"unauthorized"}`` JSON
                # but the HTTP status is still 200 with text/event-stream
                # content-type. Treat it like a 4xx so the Judge gets the
                # `target_rejected` short-circuit.
                upstream_err = _bare_error_in_sse(resp.text)
                if upstream_err is not None:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=resp.text,
                        error=f"agent.php upstream rejected: {upstream_err}",
                    )
                text = _assemble_sse_text(resp.text)
                shape = _stream_shape(resp.text)
                assigned_conv_id = _extract_assigned_conversation_id(resp.text)
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
            stream_shape=shape,
            assigned_conversation_id=assigned_conv_id,
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

    async def _pin_session_patient(self, pid: str) -> None:
        """Pin ``$_SESSION['pid']`` to ``pid`` by GETting panel.php with
        a ``?pid=`` query — panel.php calls ``setpid()`` exactly the way
        the dashboard SPA does. Used before document_upload.php (whose
        route ignores query params and reads pid from the session).
        Best-effort: a non-2xx response is logged but not raised — the
        caller will surface a clearer error from the failing route."""
        if not pid or pid == "0":
            return
        url = (
            f"{self._base_url}"
            "/interface/modules/custom_modules/oe-module-clinical-copilot/"
            f"public/panel.php?pid={pid}"
        )
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, cookies=self._cookies, follow_redirects=False
            ) as client:
                resp = await client.get(url)
                self._cookies.update(resp.cookies)
                if resp.status_code >= 400:
                    log.warning(
                        "target.set_pid_failed",
                        status_code=resp.status_code,
                        pid=pid,
                    )
        except httpx.HTTPError as e:
            log.warning("target.set_pid_error", error=repr(e), pid=pid)

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

        # ``task`` defaults to ``default_briefing`` (the kickoff path
        # that accepts a fresh conversationId). Callers wanting to
        # continue an existing conversation can pass ``task="follow_up"``
        # + ``conversation_id=<existing>`` in ``envelope.extra``; the
        # agent server requires the conversation to be owned by the
        # authenticated principal (rejected as ``invalid_envelope``
        # otherwise — happens when the kickoff hasn't been sent yet).
        #
        # The Red Team worker uses this seam to fire K seeds within
        # one plan attempt as a single conversation: seed #0 sends
        # ``default_briefing`` and gets a fresh conversationId; seeds
        # #1..K-1 send ``follow_up`` with that same conversationId,
        # so the model sees them as turns in one chat.
        task_value = str(envelope.extra.get("task") or "default_briefing")
        if task_value not in ("default_briefing", "follow_up"):
            task_value = "default_briefing"
        conv_id = str(envelope.extra.get("conversation_id") or _uuid.uuid4())

        body: dict[str, Any] = {
            "requestId": str(_uuid.uuid4()),
            "conversationId": conv_id,
            "siteId": "default",
            "patient": {"pid": pid_int, "uuid": str(envelope.extra.get("uuid", ""))},
            "task": task_value,
            "question": envelope.user_message[:2000],
        }
        # Allow extras to override (but strip our integer pid back to
        # int if extra supplies a string — preserve the schema). Keys
        # we already consumed above are filtered so a stale extra
        # doesn't clobber the canonical value (e.g. ``task=follow_up``
        # arriving as raw extra wouldn't re-set body["task"] because
        # we already chose it; the snake_case ``conversation_id``
        # extra is consumed → ``conversationId`` is already set).
        _CONSUMED = frozenset({"task", "conversation_id", "uuid", "pid", "patient"})
        body.update({k: v for k, v in envelope.extra.items() if k not in _CONSUMED})
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
            # document_upload.php reads patient context from
            # ``$_SESSION['pid']`` and 400s with ``missing_pid`` when it's
            # zero. Unlike agent.php, the upload route has no in-line
            # setpid sync from a ``?pid=`` query param. Hitting panel.php
            # with the pid pins the session-side pid via setpid() before
            # the upload fires.
            await self._pin_session_patient(pid)
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
                    # Must be one of the values OpenEMR's ExtractController
                    # allows: ['panel', 'autosweep', 'cli']. We're a
                    # scripted automated tester; 'cli' is the honest
                    # match. Anything else (e.g. the old 'cats_attack')
                    # gets a 400 invalid_trigger_source from the server.
                    "trigger_source": "cli",
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
                # extract.php returns JSON errors (e.g. invalid_trigger_source,
                # missing_pid) on the same channel as SSE pipeline events.
                # Mirror the upload-error path: empty text, raw body
                # preserved, error string set so the Judge sees the
                # explicit failure marker rather than having to infer
                # "this looks like an error" from the body shape.
                if extract_resp.status_code >= 400:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=extract_resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=extract_resp.text,
                        error=(
                            f"extract failed: HTTP {extract_resp.status_code}"
                            f" — {extract_resp.text[:200]}"
                        ),
                    )
                # Same trap as agent.php: proxy flushes SSE headers
                # before the agent's JWT verification can fail. See
                # `_bare_error_in_sse` for the full diagnosis.
                upstream_err = _bare_error_in_sse(extract_resp.text)
                if upstream_err is not None:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    return TargetCallResult(
                        text="",
                        status_code=extract_resp.status_code,
                        latency_ms=elapsed_ms,
                        raw_body=extract_resp.text,
                        error=f"extract upstream rejected: {upstream_err}",
                    )
                text = _assemble_sse_text(extract_resp.text)
                shape = _stream_shape(extract_resp.text)
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
            stream_shape=shape,
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
            shape = _stream_shape(resp.text)
            assigned_conv_id = _extract_assigned_conversation_id(resp.text)
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return TargetCallResult(text="", status_code=0, latency_ms=elapsed_ms, error=str(e))
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return TargetCallResult(
            text=text,
            status_code=resp.status_code,
            latency_ms=elapsed_ms,
            raw_body=resp.text,
            stream_shape=shape,
            assigned_conversation_id=assigned_conv_id,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_csrf_form_token(login_html: str) -> str:
    m = _CSRF_INPUT_RE.search(login_html)
    return m.group(1) if m else ""


def _extract_assigned_conversation_id(raw: str) -> str | None:
    """Pluck the agent-assigned ``conversationId`` from a briefing SSE
    stream's ``meta`` event. The agent ignores any client-supplied
    conversationId on ``default_briefing`` and mints its own server-side
    (``briefingRunner.ts:219``), then advertises it in the first SSE
    frame: ``event: meta\\ndata: {"type":"meta","conversationId":"..."}``.
    Follow-up seeds must reference *that* id or `findOwnedById` returns
    null and the agent emits ``invalid_envelope``. Returns ``None`` when
    no meta frame carrying a string conversationId is present."""
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if not payload:
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or obj.get("type") != "meta":
            continue
        conv_id = obj.get("conversationId")
        if isinstance(conv_id, str) and conv_id:
            return conv_id
    return None


# Co-Pilot SSE event types we know about today (from
# ``openemr/agent/src/server/briefingStream.ts``). Membership here is
# not a filter — it only feeds ``stream_shape.has_unknown_event_types``
# so the Judge can notice when the agent ships an event we don't
# recognize yet (a finding that mangles the envelope produces exactly
# that signal).
_KNOWN_BRIEFING_EVENTS: frozenset[str] = frozenset(
    {
        "meta",
        "progress",
        "supervisorNarration",
        "assistantMessage",
        "done",
        "error",
        "pipelineEvent",
    }
)


def _assemble_sse_text(raw: str) -> str:
    """Return the SSE body verbatim.

    Earlier revisions of this function tried to pull "assistant content"
    out of each ``data:`` payload by scanning for a hard-coded set of
    keys (``content``/``text``/``delta``/``message``). That schema
    assumption is hostile to the use case: a successful attack is
    *exactly* the case where the Co-Pilot emits something outside the
    expected envelope (leaked tool output, raw chain-of-thought,
    unredacted prescription text, a mangled ``assistantMessage``). The
    old extractor silently discarded that content before the Judge
    could see it.

    We now hand the Judge the full SSE body. The Judge already runs its
    own ``_response_shape`` introspection (`cats.agents.judge.verifier`)
    and the LLM rubric prompts include the raw body in the "Target
    response" block — both benefit from receiving more, not less. The
    only special case is the empty body (no SSE framing at all), which
    we still return verbatim so plain-text targets keep working."""
    return raw


def _stream_shape(raw: str) -> dict[str, Any]:
    """One-pass descriptor of the SSE body's shape. Sidecar evidence
    for the Judge; never a precondition before the body is shown to it.

    Fields:

    - ``event_counts`` — per-``event:`` token tally. ``""`` is the
      synthetic key for unframed ``data:`` lines (the SSE spec lets
      ``event:`` be omitted, and the Co-Pilot still does on some
      paths).
    - ``data_payloads`` — how many ``data:`` frames were observed.
    - ``has_assistant_message`` — at least one ``assistantMessage``
      event reached us; the canonical "the model emitted a final
      reply" marker on the briefing path.
    - ``has_unknown_event_types`` — any event token outside the set
      we know about. A true here on a successful attack is itself a
      finding-worthy signal.
    - ``has_bare_error_json`` — the body is the proxy-stamped-headers
      trap (``_bare_error_in_sse`` would match). Kept here so the
      Judge sees the same signal at the shape layer.
    - ``looks_like_sse`` — at least one ``event:`` or ``data:`` line
      was present.
    """
    text = raw or ""
    event_counts: dict[str, int] = {}
    data_frames = 0
    has_assistant_message = False
    has_unknown_event_types = False
    looks_like_sse = False

    current_event = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            # Blank line ends one SSE record; reset the event token.
            current_event = ""
            continue
        if stripped.startswith("event:"):
            looks_like_sse = True
            token = stripped[len("event:") :].strip()
            current_event = token
            event_counts[token] = event_counts.get(token, 0) + 1
            if token not in _KNOWN_BRIEFING_EVENTS:
                has_unknown_event_types = True
            if token == "assistantMessage":
                has_assistant_message = True
            continue
        if stripped.startswith("data:"):
            looks_like_sse = True
            data_frames += 1
            # An unframed `data:` line (no preceding `event:`) still
            # counts; bucket under the empty key so the Judge can tell
            # framed from unframed traffic.
            if not current_event:
                event_counts[""] = event_counts.get("", 0) + 1
            # If the payload self-declares `"type":"assistantMessage"`,
            # honor it even without the `event:` framing — the wire
            # contract carries `type` redundantly for exactly this
            # reason.
            payload = stripped[len("data:") :].strip()
            if payload and payload != "[DONE]":
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    pass
                else:
                    if isinstance(obj, dict):
                        t = obj.get("type")
                        if isinstance(t, str):
                            if t == "assistantMessage":
                                has_assistant_message = True
                            if t not in _KNOWN_BRIEFING_EVENTS and not current_event:
                                has_unknown_event_types = True

    has_bare_error_json = _bare_error_in_sse(text) is not None

    return {
        "event_counts": event_counts,
        "data_payloads": data_frames,
        "has_assistant_message": has_assistant_message,
        "has_unknown_event_types": has_unknown_event_types,
        "has_bare_error_json": has_bare_error_json,
        "looks_like_sse": looks_like_sse,
        "char_count": len(text),
    }


def _bare_error_in_sse(raw: str) -> str | None:
    """Detect the "upstream proxy stamped SSE headers, then wrote a
    plain JSON error" failure mode.

    The OpenEMR ``AgentProxyController`` flushes ``text/event-stream``
    headers *before* it learns whether the agent will accept the JWT.
    When the agent rejects with 401 ``{"error": "unauthorized"}``, the
    proxy pipes that body verbatim into the already-streaming response
    — producing an HTTP 200 + ``text/event-stream`` response whose body
    is a bare JSON object with an ``error`` key and no ``data:`` /
    ``event:`` framing. The Judge can't tell this apart from a real
    pipeline reply, so we surface it explicitly here.

    Returns the upstream error code (the value of the ``error`` key)
    when the body matches, otherwise ``None``. Callers should treat a
    non-None return like a 4xx response."""
    body = (raw or "").strip()
    if not body or not body.startswith("{"):
        return None
    # Any SSE framing at all → real stream; not our case.
    if "data:" in body or body.startswith("event:"):
        return None
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    code = obj.get("error")
    if isinstance(code, str) and code:
        return code
    return None
