"""Unit tests for the SSE text-assembly helper. The Co-Pilot's briefing
endpoint emits `data: {...}\\n\\n` lines with `content` / `text` keys
per chunk; we walk the lines and concatenate them."""

from __future__ import annotations

from cats.target.client import _assemble_sse_text


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
