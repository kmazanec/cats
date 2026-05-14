"""Patient selection for Red Team runs.

Until now every attack landed on OpenEMR ``pid=1`` (Ted Shaw). That
hid a chunk of the threat surface: chart contents shape what the
Co-Pilot retrieves, which shapes what an injection can plausibly
piggyback on, which shapes whether the Judge sees a successful breach.
A `cross_patient_leak` probe against the same patient every time is
also a degenerate test.

We pick one PID per *run* (one ``(category, technique)`` scenario per
the Week-3 brief). All seeds and variant turns of a single run hit the
same patient so the conversation context stays coherent inside one
OpenEMR session; different runs in the same campaign land on
different patients so the campaign rollup covers chart variance.

Selection is deterministic on ``run_id`` (stable hash → modular index)
so a worker crash + resume re-picks the same patient, and regression
replays of a recorded run hit the same chart.

The PID list is the demo dataset seeded by
``openemr/sql/example_patient_data.sql`` — verified-present rows we
know the Co-Pilot can retrieve. Keep it in sync when new demo
patients are added on the OpenEMR side.
"""

from __future__ import annotations

import hashlib
from uuid import UUID

# Demographic-diverse subset of the seeded demo patients in
# openemr/sql/example_patient_data.sql. Span: age (40s-90s), sex,
# language, occupation, comorbidity profile - the axes most likely to
# shift the Co-Pilot's chart synthesis and therefore the surface that
# attacks can latch onto.
DEMO_PIDS: tuple[int, ...] = (
    1,  # Ted Shaw           — M, 1947
    4,  # Eduardo Perez      — M, 1957, Manager of Transportation
    5,  # Farrah Rolle       — F, 1973, Latina
    8,  # Nora Cohen         — F, 1967, Spanish speaker
    17,  # Jim Moses          — M, 1945
    18,  # Richard Jones      — M, 1940
    22,  # Ilias Jenane       — F, 1933, retired teacher
    25,  # John Dockerty      — M, 1977, PT
    26,  # James Janssen      — M, 1966, office manager
    30,  # Jason Binder       — M, 1961, real estate agent
    34,  # Robert Dickey      — M, 1955, project manager
    35,  # Jillian Mahoney    — F, 1968
    40,  # Wallace Buckley    — M, 1952, accountant
    41,  # Brent Perez        — M, 1960, airline mechanic
)


def choose_pid_for_run(run_id: UUID) -> int:
    """Deterministically pick a demo PID for one Red Team run.

    Stable across worker restarts and replays: same ``run_id`` always
    yields the same PID, so resumes and regression-replays target the
    same chart the original run did.

    We hash the UUID rather than using its int directly because UUIDs
    generated near in time share high-order bits — modding the raw int
    would cluster co-temporal runs onto a narrow slice of the patient
    pool. SHA-256 of the canonical string form distributes uniformly.
    """
    if not DEMO_PIDS:  # defensive — the constant above is non-empty
        return 1
    digest = hashlib.sha256(str(run_id).encode("utf-8")).digest()
    idx = int.from_bytes(digest[:8], "big") % len(DEMO_PIDS)
    return DEMO_PIDS[idx]
