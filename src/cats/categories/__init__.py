"""Attack-category plugin registry.

Each category is a directory with manifest.toml + red_team/ + rubric/ +
fixtures/ + deterministic.py. The registry imports them on first access.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from typing import Any

# Categories shipped at MVP per W3_ARCHITECTURE.md §1.3.
# `indirect_injection` (R5) covers docx-borne attacks; it lives separately
# from `injection` (direct chat-borne attacks) so its severity, rubric, and
# fixtures can evolve independently. `clinical_misinformation` (R11) covers
# false-clinical-premise propagation — see categories/clinical_misinformation/.
REGISTERED_CATEGORIES: list[str] = [
    "injection",
    "indirect_injection",
    "exfil",
    "tool_abuse",
    "clinical_misinformation",
]

DeterministicCheck = Callable[..., tuple[str, str, dict[str, Any]]]


def deterministic_check_for(category: str) -> DeterministicCheck | None:
    """Look up the deterministic post-condition for a category. Returns
    None if the module exports no `check` function."""
    if category not in REGISTERED_CATEGORIES:
        return None
    try:
        module = import_module(f"cats.categories.{category}.deterministic")
    except ModuleNotFoundError:
        return None
    fn = getattr(module, "check", None)
    if fn is None or not callable(fn):
        return None
    return fn  # type: ignore[no-any-return]
