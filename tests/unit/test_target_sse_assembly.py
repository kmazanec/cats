"""Unit tests for the SSE text-assembly helper. The Co-Pilot's briefing
endpoint emits `data: {...}\\n\\n` lines with `content` / `text` keys
per chunk; we walk the lines and concatenate them."""

from __future__ import annotations

from cats.target.client import (
    _assemble_sse_text,
    _bare_error_in_sse,
    _extract_assigned_conversation_id,
)


def test_assembles_content_lines() -> None:
    raw = (
        'data: {"type":"section","content":"Hello "}\n\n'
        'data: {"type":"section","content":"there."}\n\n'
        'data: {"type":"complete"}\n\n'
    )
    out = _assemble_sse_text(raw)
    assert "Hello " in out
    assert "there." in out


def test_assembles_text_and_delta_keys() -> None:
    raw = 'data: {"text":"part-a"}\n\ndata: {"delta":"part-b"}\n\ndata: {"message":"part-c"}\n\n'
    out = _assemble_sse_text(raw)
    assert "part-a" in out
    assert "part-b" in out
    assert "part-c" in out


def test_skips_done_marker() -> None:
    raw = 'data: {"content":"hi"}\n\ndata: [DONE]\n\n'
    out = _assemble_sse_text(raw)
    assert "hi" in out
    assert "[DONE]" not in out


def test_falls_back_to_raw_when_not_sse() -> None:
    raw = "plain text, no data: prefix"
    assert _assemble_sse_text(raw) == raw


def test_tolerates_non_json_data_payloads() -> None:
    raw = "data: not-json-but-still-content\n\n"
    out = _assemble_sse_text(raw)
    assert "not-json-but-still-content" in out


def test_extract_conv_id_from_meta_event() -> None:
    raw = (
        "event: meta\n"
        'data: {"type":"meta","conversationId":"abc-123","requestId":"r-9"}\n\n'
        "event: progress\n"
        'data: {"type":"progress","stage":"retrieve"}\n\n'
    )
    assert _extract_assigned_conversation_id(raw) == "abc-123"


def test_extract_conv_id_returns_none_when_no_meta_event() -> None:
    raw = 'data: {"type":"section","content":"hi"}\n\ndata: {"type":"complete"}\n\n'
    assert _extract_assigned_conversation_id(raw) is None


def test_extract_conv_id_returns_none_when_meta_lacks_conv_id() -> None:
    raw = 'data: {"type":"meta","requestId":"r-9"}\n\n'
    assert _extract_assigned_conversation_id(raw) is None


def test_extract_conv_id_ignores_non_meta_events_with_conv_id_field() -> None:
    raw = 'data: {"type":"progress","conversationId":"should-not-match"}\n\n'
    assert _extract_assigned_conversation_id(raw) is None


# ---------------------------------------------------------------------------
# Bare-error-in-SSE detection — the "proxy stamped SSE headers, then upstream
# rejected" failure mode (OpenEMR proxy<->agent JWT iss mismatch surfaces this way).
# ---------------------------------------------------------------------------


def test_bare_error_detects_unauthorized() -> None:
    # The exact shape we observed when the agent rejected the JWT —
    # bare JSON body, no SSE framing, served with text/event-stream
    # content-type.
    assert _bare_error_in_sse('{"error":"unauthorized"}') == "unauthorized"


def test_bare_error_strips_whitespace() -> None:
    assert _bare_error_in_sse('  \n {"error":"forbidden"}  \n') == "forbidden"


def test_bare_error_returns_none_on_real_sse_stream() -> None:
    # Normal SSE traffic must NOT trip the detector even if a data
    # payload happens to look like a JSON object with an `error` key.
    raw = (
        'event: pipeline.start\ndata: {"stage":"extract"}\n\n'
        'event: pipeline.error\ndata: {"type":"error","code":"foo"}\n\n'
    )
    assert _bare_error_in_sse(raw) is None


def test_bare_error_returns_none_when_no_error_key() -> None:
    assert _bare_error_in_sse('{"ok":true}') is None


def test_bare_error_returns_none_on_empty_body() -> None:
    assert _bare_error_in_sse("") is None
    assert _bare_error_in_sse(None) is None  # type: ignore[arg-type]


def test_bare_error_returns_none_on_non_json() -> None:
    assert _bare_error_in_sse("plain text response") is None


def test_bare_error_returns_none_when_error_is_not_string() -> None:
    # Defensive: a JSON object whose `error` key is null or numeric
    # shouldn't be classified as an upstream rejection.
    assert _bare_error_in_sse('{"error":null}') is None
    assert _bare_error_in_sse('{"error":42}') is None
