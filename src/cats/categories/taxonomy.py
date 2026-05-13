"""Per-category taxonomy lookup.

Each category ships a ``taxonomy.toml`` that maps technique keys to MITRE
ATLAS + OWASP LLM IDs. The documentation node consults this when promoting
a Finding so every finding carries the most-specific industry-standard
labels its technique earns, rather than a category-wide default.

The TOML schema (see ``cats/categories/<category>/taxonomy.toml``)::

    [default]
    atlas_technique_id = "AML.T0051"
    owasp_llm_id = "LLM01"
    description = "..."

    [techniques.<key>]
    atlas_technique_id = "..."
    owasp_llm_id = "..."
    description = "..."

A missing technique key falls back to ``[default]``. A missing category
returns the all-``None`` :class:`TaxonomyLabel` — safe but unlabeled, so
the finding still records.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class TaxonomyLabel:
    atlas_technique_id: str | None
    owasp_llm_id: str | None
    description: str = ""


_EMPTY = TaxonomyLabel(atlas_technique_id=None, owasp_llm_id=None, description="")


@lru_cache(maxsize=16)
def _load(category: str) -> dict[str, object]:
    """Read ``cats/categories/<category>/taxonomy.toml`` once and cache it.
    Returns ``{}`` if the file is missing (the category may not have one)."""
    try:
        ref = resources.files(f"cats.categories.{category}").joinpath("taxonomy.toml")
        with ref.open("rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, ModuleNotFoundError):
        return {}


def lookup(category: str, technique: str = "") -> TaxonomyLabel:
    """Look up the MITRE ATLAS + OWASP LLM labels for ``(category, technique)``.

    Falls back to the category's ``[default]`` block if ``technique`` is
    empty or unknown. Returns an all-``None`` label if the category itself
    has no taxonomy file — callers should treat ``None`` IDs as "unlabeled,
    record the finding anyway."
    """
    data = _load(category)
    if not data:
        return _EMPTY

    techniques = data.get("techniques", {}) or {}
    if technique and isinstance(techniques, dict):
        entry = techniques.get(technique)
        if isinstance(entry, dict):
            return TaxonomyLabel(
                atlas_technique_id=entry.get("atlas_technique_id"),
                owasp_llm_id=entry.get("owasp_llm_id"),
                description=entry.get("description", ""),
            )

    default = data.get("default", {}) or {}
    if isinstance(default, dict):
        return TaxonomyLabel(
            atlas_technique_id=default.get("atlas_technique_id"),
            owasp_llm_id=default.get("owasp_llm_id"),
            description=default.get("description", ""),
        )
    return _EMPTY
