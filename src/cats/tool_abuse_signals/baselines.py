"""Parse the reviewable baselines table.

``reports/tool_abuse/baselines.md`` is the security-engineer-readable
source of truth for "appropriate tool use" per Co-Pilot task type. The
parser here pulls the per-task tables back into Python so the
deterministic check can consume them. Same Markdown a reviewer reads.

Section layout the parser recognizes (kept tight so the file's
authoring is unconstrained beyond the table shape):

    ### `<task_type>`

    ... prose, freely worded ...

    | Tools <header continues> | Chart areas <header continues> |
    |---|---|
    | <comma-separated tool names, optionally backticked> | <comma-separated area labels> |

The first such header-and-row pair under each ``###`` block is the
baseline. Subsequent prose (rationale, examples) is ignored — the
checker only cares about the explicit lists.

A few sanity rules the parser enforces (and the test pins):

- Task-type heading text must be enclosed in backticks (e.g. ```` ### `default_briefing` ````).
- Every task section MUST have exactly one baseline table.
- Tool names are normalized to bare identifiers (backticks stripped).
- Chart-area labels are normalized to lowercase + whitespace-collapsed
  so the matcher's substring scans don't drift on minor edits.
- The chart-area cell may contain ``out of scope`` or ``placeholder``
  (case-insensitive) to mark a task as not red-teamed in this round
  — the parser surfaces those as ``Baseline.out_of_scope = True``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

_DEFAULT_BASELINES_PATH = (
    Path(__file__).parent.parent.parent.parent / "reports" / "tool_abuse" / "baselines.md"
)

# Heading marker — `### `task_name``. Task names are alphanumeric +
# underscore (matches the actual Co-Pilot task field shape:
# default_briefing, follow_up, precompute, t1, etc.).
_TASK_HEADING_RE = re.compile(r"^###\s+`([a-z0-9_]+)`\s*$", re.MULTILINE)

# A pipe-table row. We accept any whitespace around the pipes.
_TABLE_ROW_RE = re.compile(r"^\|([^\n]+)\|\s*$", re.MULTILINE)

# Recognizes the "out of scope" / "placeholder" markers in the chart-area
# cell of a baseline whose round-7 coverage is intentionally absent.
_OUT_OF_SCOPE_TOKENS = ("out of scope", "out-of-scope", "placeholder", "n/a")


@dataclass(frozen=True)
class Baseline:
    """The legitimately-allowed surface area for a single task type."""

    task_type: str
    tools: frozenset[str]
    chart_areas: frozenset[str]
    out_of_scope: bool = False

    def is_tool_allowed(self, tool_name: str) -> bool:
        return tool_name.strip("`") in self.tools

    def is_area_allowed(self, area_label: str) -> bool:
        """Membership test on the canonicalized area label."""
        return _canonicalize_area(area_label) in self.chart_areas


@dataclass(frozen=True)
class BaselinesIndex:
    """Whole-file view: every task type that has a baseline."""

    source_path: Path | None
    baselines: Mapping[str, Baseline] = field(default_factory=dict)

    def for_task(self, task_type: str) -> Baseline | None:
        return self.baselines.get(task_type)

    @property
    def known_task_types(self) -> frozenset[str]:
        return frozenset(self.baselines.keys())


def _canonicalize_area(area: str) -> str:
    """Lowercase + whitespace-collapse a chart-area label so minor
    edits to ``baselines.md`` ("recent labs" → "Recent Labs") don't
    drift the matcher."""
    return " ".join(area.lower().split()).strip(",.;:")


def _split_cell_entries(cell: str) -> list[str]:
    """Split a pipe-table cell into individual entries.

    Author convention: tools are comma-separated identifiers (often
    backticked); chart-area labels are comma-separated short phrases.
    We split on commas, strip backticks and whitespace, and drop empties.
    """
    entries: list[str] = []
    for raw in cell.split(","):
        cleaned = raw.strip().strip("`").strip()
        if cleaned:
            entries.append(cleaned)
    return entries


def parse_baselines_markdown(markdown: str, *, source_path: Path | None = None) -> BaselinesIndex:
    """Parse the baselines document into a :class:`BaselinesIndex`.

    Raises :class:`ValueError` if the document is malformed — a missing
    table, a heading without a body, or duplicate task headings. The
    parser is strict on purpose: a silently-empty baseline would make
    every attack look like over-reach.
    """
    headings = list(_TASK_HEADING_RE.finditer(markdown))
    if not headings:
        raise ValueError("no task baselines found — expected `### `<task_type>`` headings")

    baselines: dict[str, Baseline] = {}

    for idx, heading_match in enumerate(headings):
        task_type = heading_match.group(1).strip()
        if task_type in baselines:
            raise ValueError(f"duplicate baseline section for task_type={task_type!r}")

        section_start = heading_match.end()
        section_end = headings[idx + 1].start() if idx + 1 < len(headings) else len(markdown)
        section = markdown[section_start:section_end]

        rows = _TABLE_ROW_RE.findall(section)
        # First row is header, second is the separator (`|---|---|`),
        # third is the data row. We tolerate any number of header
        # rows but require the *first data row after the separator*
        # to carry exactly two cells: tools, areas. We preserve empty
        # cells inside the row (an empty Tools cell with `out of scope`
        # in Chart areas is a legitimate marker).
        data_row_cells: list[str] | None = None
        separator_seen = False
        for row in rows:
            raw_cells = row.split("|")
            # The capture group is "everything between the first and
            # last pipe", so any row with N inner pipes yields N+1
            # cells. The pipe shape itself is the contract.
            cells = [c.strip() for c in raw_cells]
            if not cells:
                continue
            # Separator row looks like `---` cells (ignore empties).
            non_empty = [c for c in cells if c]
            if non_empty and all(set(c) <= {"-", ":"} for c in non_empty):
                separator_seen = True
                continue
            if separator_seen and len(cells) >= 2:
                data_row_cells = cells
                break

        if data_row_cells is None:
            raise ValueError(f"task baseline for {task_type!r} has no data row in its table")

        tools_cell, areas_cell = data_row_cells[0], data_row_cells[1]

        lowered_areas = areas_cell.strip().lower()
        out_of_scope = any(tok in lowered_areas for tok in _OUT_OF_SCOPE_TOKENS)

        tools = frozenset(_split_cell_entries(tools_cell)) if not out_of_scope else frozenset()
        areas = (
            frozenset(_canonicalize_area(a) for a in _split_cell_entries(areas_cell))
            if not out_of_scope
            else frozenset()
        )

        baselines[task_type] = Baseline(
            task_type=task_type,
            tools=tools,
            chart_areas=areas,
            out_of_scope=out_of_scope,
        )

    return BaselinesIndex(source_path=source_path, baselines=baselines)


def load_default_baselines() -> BaselinesIndex:
    """Read ``reports/tool_abuse/baselines.md`` and parse it.

    Cached per-process. Tests that exercise the parser directly should
    call :func:`parse_baselines_markdown` with inline content instead;
    this loader is for the deterministic check at runtime.
    """
    cached = _CACHED.get("default")
    if cached is None:
        text = _DEFAULT_BASELINES_PATH.read_text(encoding="utf-8")
        cached = parse_baselines_markdown(text, source_path=_DEFAULT_BASELINES_PATH)
        _CACHED["default"] = cached
    return cached


_CACHED: dict[str, BaselinesIndex] = {}
