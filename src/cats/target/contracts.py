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
    """Return value of `TargetClient.attack`. `text` is what the Judge
    inspects; `raw_body` is preserved for the AttackExecution row and
    forensic replay.

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
    error: str | None = None
    assigned_conversation_id: str | None = None
