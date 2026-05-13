"""Pydantic mirrors of the target Co-Pilot's HTTP shapes.

These are *our* model of the target's API, not imports from the openemr
repo (that boundary is read-only by design). They'll grow as we hit more
endpoints.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CopilotRequest(BaseModel):
    """Generic shape of a Co-Pilot API request body."""

    endpoint: str
    method: str = "POST"
    payload: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)


class CopilotResponse(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    latency_ms: int = 0
    error: str | None = None


class AttachmentSpec(BaseModel):
    """A file the attacker wants uploaded as part of an attack envelope.

    Used by docx-borne indirect injection (R5): the Red Team's
    indirect_injection specialist returns the .docx bytes; the executor
    wraps them in this spec; the target client POSTs multipart/form-data
    to OpenEMR's ``document_upload.php`` and then triggers extraction
    via ``extract.php``. The deterministic check runs against the SSE
    pipeline events extract.php streams back.
    """

    model_config = ConfigDict(frozen=True)

    filename: str
    content_type: str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    data: bytes


class AttackEnvelope(BaseModel):
    """High-level shape the graph passes to the TargetClient. The client
    knows how to translate this into the target's actual HTTP contract
    (chat-style ``agent.php`` proxy vs. docx upload + ``extract.php``
    pipeline vs. the local-dev ``/v1/agent/*`` shortcut).

    When ``attachment`` is set the target client takes the upload path
    instead of the chat path. ``user_message`` is then the
    extraction-trigger prompt (typically a "summarize this document"
    framing — the exact text depends on what extract.php sends through
    to the agent)."""

    model_config = ConfigDict(frozen=True)

    user_message: str
    canary: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
    attachment: AttachmentSpec | None = None


class TargetCallResult(BaseModel):
    """Return value of `TargetClient.attack`. ``text`` is the raw SSE
    body verbatim — the Judge (and the category deterministic checks)
    reason over the full event stream rather than a schema-parsed
    extract. The previous schema-rigid extractor silently dropped any
    content that didn't match a hard-coded key allowlist, which is
    actively wrong for adversarial testing: an attack that mangles the
    Co-Pilot's ``assistantMessage`` envelope is *precisely* the kind of
    finding we cannot afford to filter out before the Judge sees it.

    ``stream_shape`` is a sidecar descriptor produced by a single pass
    over the body: per-event-type counts, whether a final
    ``assistantMessage`` ever arrived, whether any unknown event types
    showed up, whether the body is the bare-error trap. The Judge can
    consult it without re-parsing.

    ``raw_body`` is kept for backwards compatibility with callers that
    distinguish the verbatim HTTP body from the assembled ``text``;
    today they're identical on the SSE paths but the seam lets future
    non-SSE channels diverge.

    ``assigned_conversation_id`` is the agent-assigned conversationId
    parsed from the SSE ``meta`` event on a ``default_briefing`` kickoff.
    The agent ignores any client-supplied conversationId on kickoff and
    mints its own server-side, so the Red Team worker must use *that*
    id (not the one CATS minted) when firing follow-up seeds into the
    same conversation. ``None`` when no ``meta`` event was seen
    (errors, non-proxy paths, malformed streams)."""

    text: str
    status_code: int
    latency_ms: int
    raw_body: dict[str, Any] | str | None = None
    stream_shape: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    assigned_conversation_id: str | None = None
