"""Markdown case loader.

Each eval case lives in its own ``.md`` file under
``evals/cases/<agent>/``. The file is parsed by H2 sections; the
loader extracts:

- ``title`` — the H1 line.
- ``description`` — the first ``>`` blockquote line.
- ``tags`` — bullet list under ``## Tags``, each bullet a
  ``key: value`` pair.
- ``inputs`` — the first JSON fenced block under ``## Inputs``.
- ``expected`` — the first JSON fenced block under ``## Expected``.
- ``notes`` — the prose under ``## Notes`` (preserved verbatim).

The goal is markdown-only authoring. A human edits a ``.md`` file
the same way they'd edit a runbook entry; no JSON-Lines, no
YAML frontmatter, no per-suite schema knowledge.

A malformed file raises ``CaseParseError`` with the file path and
the offending section so the author can fix it without grep.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_H1_RE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
_H2_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
_BLOCKQUOTE_RE = re.compile(r"^>\s+(.+)$", re.MULTILINE)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)
_BULLET_RE = re.compile(r"^[-*]\s+([A-Za-z_][\w\- ]*?):\s*(.+?)\s*$", re.MULTILINE)


class CaseParseError(ValueError):
    """Raised when a case file can't be parsed. Carries the path + reason."""


@dataclass(frozen=True)
class Case:
    case_id: str
    path: Path
    title: str
    description: str
    tags: dict[str, str]
    inputs: dict[str, Any]
    expected: dict[str, Any]
    notes: str = ""
    raw_sections: dict[str, str] = field(default_factory=dict)

    @property
    def agent(self) -> str:
        return self.tags.get("agent", "")


def _split_h2_sections(body: str) -> dict[str, str]:
    matches = list(_H2_RE.finditer(body))
    sections: dict[str, str] = {}
    for i, m in enumerate(matches):
        name = m.group(1).strip().lower()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[name] = body[start:end].strip()
    return sections


def _extract_first_json(section_body: str, *, section_name: str, path: Path) -> dict[str, Any]:
    fence = _JSON_FENCE_RE.search(section_body)
    if not fence:
        raise CaseParseError(f"{path}: section '## {section_name}' has no ```json block")
    try:
        parsed = json.loads(fence.group(1))
    except json.JSONDecodeError as e:
        raise CaseParseError(
            f"{path}: section '## {section_name}' has invalid JSON: {e.msg} (line {e.lineno})"
        ) from e
    if not isinstance(parsed, dict):
        raise CaseParseError(
            f"{path}: section '## {section_name}' JSON must be an object, got {type(parsed).__name__}"
        )
    return parsed


def _parse_tags(section_body: str) -> dict[str, str]:
    return {
        m.group(1).strip().lower(): m.group(2).strip() for m in _BULLET_RE.finditer(section_body)
    }


def parse_case(path: Path) -> Case:
    text = path.read_text(encoding="utf-8")

    h1 = _H1_RE.search(text)
    if not h1:
        raise CaseParseError(f"{path}: missing H1 title line")
    title = h1.group(1).strip()

    # Description is the first blockquote line *before* any H2.
    first_h2 = _H2_RE.search(text)
    head = text[: first_h2.start()] if first_h2 else text
    bq = _BLOCKQUOTE_RE.search(head)
    description = bq.group(1).strip() if bq else ""

    sections = _split_h2_sections(text)
    if "tags" not in sections:
        raise CaseParseError(f"{path}: missing '## Tags' section")
    if "inputs" not in sections:
        raise CaseParseError(f"{path}: missing '## Inputs' section")
    if "expected" not in sections:
        raise CaseParseError(f"{path}: missing '## Expected' section")

    tags = _parse_tags(sections["tags"])
    if "agent" not in tags:
        raise CaseParseError(f"{path}: '## Tags' must include an 'agent:' bullet")

    inputs = _extract_first_json(sections["inputs"], section_name="Inputs", path=path)
    expected = _extract_first_json(sections["expected"], section_name="Expected", path=path)

    return Case(
        case_id=path.stem,
        path=path,
        title=title,
        description=description,
        tags=tags,
        inputs=inputs,
        expected=expected,
        notes=sections.get("notes", ""),
        raw_sections=sections,
    )


def load_cases(agent: str, *, root: Path | None = None) -> list[Case]:
    """Load every ``.md`` file under ``evals/cases/<agent>/``, sorted by filename."""
    base = (root or Path(__file__).parent / "cases") / agent
    if not base.exists():
        raise FileNotFoundError(f"no cases dir for agent={agent!r} at {base}")
    cases = [parse_case(p) for p in sorted(base.glob("*.md"))]
    mismatched = [c for c in cases if c.agent and c.agent != agent]
    if mismatched:
        bad = ", ".join(f"{c.case_id} (agent={c.agent!r})" for c in mismatched)
        raise CaseParseError(f"cases under {base} have mismatched agent tag: {bad}")
    return cases
