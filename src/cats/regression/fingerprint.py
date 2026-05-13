"""Behavioral-fingerprint primitives — gate 3 of the §6.4 triple gate.

Just cosine similarity between two embedding vectors plus a threshold
comparison. Lives in its own module so the runner and tests share one
implementation and a future cluster-of-exemplars upgrade has a single
edit point.
"""

from __future__ import annotations


def cosine_similarity(a: list[float] | None, b: list[float] | None) -> float | None:
    """Return cosine similarity in [-1, 1] or ``None`` if either vector
    is missing/empty/zero. A ``None`` result means the caller cannot
    score the gate — surface as "unclear" rather than "fail."
    """
    if not a or not b:
        return None
    if len(a) != len(b):
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(y * y for y in b) ** 0.5
    if mag_a == 0.0 or mag_b == 0.0:
        return None
    return float(dot / (mag_a * mag_b))


def fingerprint_matches(
    response_embedding: list[float] | None,
    exemplar_embedding: list[float] | None,
    *,
    threshold: float,
) -> bool | None:
    """Return True/False/None for the gate-3 result. ``None`` means the
    exemplar is missing or the response wasn't embeddable — caller
    routes the case to ``needs_review`` rather than auto-passing.
    """
    sim = cosine_similarity(response_embedding, exemplar_embedding)
    if sim is None:
        return None
    return sim >= threshold
