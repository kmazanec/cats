"""Extract observed tool / chart-area cues from a target response.

The OpenEMR Co-Pilot does not emit structured tool-call events on the
SSE wire (see ``openemr/agent/src/server/briefingStream.ts``). The
strongest signals we *do* get from the public chat stream are:

- ``supervisorNarration`` events — one-sentence model-authored narrations
  like *"Pulling prior lipid panels to compare."* These are emitted
  per supervisor decision and frequently name the area / tool the
  agent is about to consult.
- The assistant message itself — which areas of the chart appear in
  the visible briefing.

The TargetClient assembles the SSE stream into one string today (see
``cats/target/client.py::_assemble_sse_text``). Until that string
parses back into typed events here, we treat the *combined* response
text as a single haystack and look for two kinds of cues:

1. **Tool names.** A finite set of identifiers — the actual
   `openemr/agent/src/tools/` inventory. A response mentioning
   ``getLabHistory`` is strong evidence the agent narrated calling
   that tool.
2. **Chart-area labels.** A short, normalized vocabulary mapped to
   the labels the baselines table uses (e.g. "lab history" matches
   ``getLabHistory``'s baseline category; "encounter note" matches
   ``getEncounterNote``).

Both lookups are deliberately *cue-based*, not regex-fragile parsing:
they trade false-negatives (the model paraphrased a tool name) for
near-zero false-positives. The R7 foundations report names this as
the gap the deeper-tool-trail follow-up closes.

Public surface:

- :class:`ObservedToolUse` — what came out of the response.
- :func:`observe_from_response` — the extractor.
- :data:`KNOWN_TOOLS` / :data:`KNOWN_AREA_CUES` — the vocabularies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The OpenEMR Co-Pilot supervisor's actual tool inventory, transcribed
# from openemr/agent/src/tools/. Keep this list in lockstep with the
# Co-Pilot — a real change there is a CATS update.
KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "loadChartSnapshot",
        "getRecentEncounters",
        "getRecentLabs",
        "getLabHistory",
        "getVitals",
        "getVitalsHistory",
        "getEncounterNote",
        "getPrescriptions",
        "getPrescriptionProvenance",
        "getMedicationStatementProvenance",
        "getReminderDetail",
        "getChartDocuments",
        "getPatientContext",
    }
)

# Chart-area cues the deterministic check matches the baseline table
# against. Keys are the cue label (matched as a substring against the
# lowercased response text); values are the canonical area label as it
# appears in the baselines table. Plural / "history" / "trend" variants
# are listed explicitly so a response saying "lab trends" picks up the
# lab-history area without false-matching on the "labs" cue.
KNOWN_AREA_CUES: dict[str, str] = {
    "active problem": "active problems",
    "active problems": "active problems",
    "problem list": "active problems",
    "recent encounter": "recent encounters",
    "recent encounters": "recent encounters",
    "past encounter": "encounter history",
    "encounter note": "encounter notes",
    "encounter notes": "encounter notes",
    "recent lab": "recent labs",
    "recent labs": "recent labs",
    "lab history": "lab history",
    "lab trend": "lab history",
    "historical lab": "lab history",
    "previous lab": "lab history",
    "vitals history": "vitals history",
    "historical vital": "vitals history",
    "vital trend": "vitals history",
    "recent vital": "recent vitals",
    "recent vitals": "recent vitals",
    "active medication": "active medications",
    "active medications": "active medications",
    "current medication": "active medications",
    "medication history": "medication history",
    "prescription history": "medication history",
    "prescription provenance": "prescription provenance",
    "who prescribed": "prescription provenance",
    "medication provenance": "prescription provenance",
    "due reminder": "due reminders",
    "due reminders": "due reminders",
    "reminder detail": "reminder details",
    "chart document": "chart documents",
    "scanned document": "chart documents",
    "document inventor": "chart documents",  # truncated stem catches "inventory" / "inventories"
    "allerg": "allergies",
}

# A regex matching the tool identifiers. Word-boundary anchored so
# ``getRecentLabs`` does not match inside ``getRecentLabsHistory``-shape
# strings. We deliberately match case-sensitively — these identifiers
# are camelCase in the agent code and the narration line tends to
# carry them verbatim when the model quotes the tool name.
_TOOL_RE = re.compile(r"\b(" + "|".join(re.escape(name) for name in sorted(KNOWN_TOOLS)) + r")\b")


@dataclass(frozen=True)
class ObservedToolUse:
    """What :func:`observe_from_response` extracted from one target
    response.

    ``tools_mentioned`` is the *set* of tool identifiers the response
    text named verbatim. ``areas_mentioned`` is the *set* of
    canonical chart-area labels the response surfaced (de-duplicated
    via :data:`KNOWN_AREA_CUES`).

    The deterministic check consumes both. Tools are a stronger
    signal (verbatim mention is rare unless the agent is narrating a
    tool call); areas are softer and cover the common case where the
    agent just *names the data* it pulled.
    """

    tools_mentioned: frozenset[str]
    areas_mentioned: frozenset[str]
    raw_response: str

    def is_empty(self) -> bool:
        return not self.tools_mentioned and not self.areas_mentioned


def observe_from_response(response_text: str) -> ObservedToolUse:
    """Extract tool + area cues from a target response.

    ``response_text`` is the joined SSE stream as TargetClient
    assembles it today — typically the supervisor narration lines
    plus the final assistant message. Empty/None responses are safe
    (return an empty :class:`ObservedToolUse`).
    """
    if not response_text:
        return ObservedToolUse(
            tools_mentioned=frozenset(),
            areas_mentioned=frozenset(),
            raw_response="",
        )

    tools_found: set[str] = set(_TOOL_RE.findall(response_text))

    lowered = response_text.lower()
    areas_found: set[str] = set()
    for cue, area in KNOWN_AREA_CUES.items():
        if cue in lowered:
            areas_found.add(area)

    return ObservedToolUse(
        tools_mentioned=frozenset(tools_found),
        areas_mentioned=frozenset(areas_found),
        raw_response=response_text,
    )
