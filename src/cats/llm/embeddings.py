"""Embedding client for the R8 regression-fingerprint gate.

The behavioral-fingerprint gate (§6.4 gate 3) needs sentence-level
embeddings to ask "does this response embed close to the captured
safe-refusal exemplar?" The platform's existing LLM client surface is
chat-only; embeddings ride a separate OpenRouter endpoint.

Design mirrors :mod:`cats.llm.client`:

- :class:`EmbeddingClient` is a Protocol; production wires
  :class:`RealEmbeddingClient` (HTTP to OpenRouter), tests inject
  :class:`FakeEmbeddingClient`.
- Process-global override is installed via :func:`install_override`,
  cleared with ``install_override(None)``. Always reset in a
  ``finally`` or autouse fixture.

The model id comes from ``get_settings().regression_embedding_model``;
default ``openai/text-embedding-3-small`` (1536 dims, sub-cent
per call at typical response sizes).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import httpx

from cats.config import get_settings


@runtime_checkable
class EmbeddingClient(Protocol):
    async def embed(self, text: str) -> list[float]: ...


class RealEmbeddingClient:
    """Production client. Calls OpenRouter's ``/embeddings`` endpoint."""

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self._api_key = api_key or get_settings().openrouter_api_key
        self._base_url = get_settings().openrouter_base_url.rstrip("/")
        self._model = model or get_settings().regression_embedding_model

    async def embed(self, text: str) -> list[float]:
        # Empty input is meaningless for cosine; short-circuit with a
        # zero vector rather than burning a paid call. Caller treats
        # any zero-vector as the "gate unclear" case.
        if not text:
            return []
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._base_url}/embeddings",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": self._model, "input": text},
            )
            resp.raise_for_status()
            body = resp.json()
        data = body.get("data") or []
        if not data:
            return []
        vec = data[0].get("embedding") or []
        return [float(x) for x in vec]


@dataclass
class FakeEmbeddingClient:
    """Deterministic embedding client for tests. Produces a 32-dim vector
    from a SHA-256 of the input string, normalized to unit length. Two
    inputs that differ in even one byte yield very different vectors
    (cosine ≈ 0 in expectation), while identical inputs produce
    identical vectors (cosine = 1.0). The ``aliases`` map lets a test
    declare "these N strings should embed to the same vector" — useful
    for simulating the "model refuses differently now" case without
    sticking real strings into the test."""

    aliases: dict[str, str] = field(default_factory=dict)
    call_log: list[str] = field(default_factory=list)

    async def embed(self, text: str) -> list[float]:
        self.call_log.append(text)
        if not text:
            return []
        canonical = self.aliases.get(text, text)
        # 32 floats derived from successive SHA-256 hashes; pseudo-stable
        # but bounded so we don't depend on hashlib internals.
        material = hashlib.sha256(canonical.encode("utf-8")).digest()
        # 32 bytes / 1 byte per value -> 32 values in [-1, 1].
        floats = [((b / 255.0) * 2.0 - 1.0) for b in material]
        # Normalize so cosine reduces to dot product.
        magnitude = sum(x * x for x in floats) ** 0.5 or 1.0
        return [x / magnitude for x in floats]


_OVERRIDE: EmbeddingClient | None = None


def install_override(client: EmbeddingClient | None) -> None:
    """Test seam mirroring :func:`cats.llm.client.install_override`. Pass
    a FakeEmbeddingClient to make every :func:`get_embedding_client` call
    return it; pass ``None`` to clear."""
    global _OVERRIDE
    _OVERRIDE = client


def get_embedding_client() -> EmbeddingClient:
    """Factory. Returns the active override if any; otherwise Real when an
    OpenRouter key is configured, Fake otherwise."""
    if _OVERRIDE is not None:
        return _OVERRIDE
    if get_settings().openrouter_api_key and not get_settings().openrouter_api_key.startswith(
        "test-"
    ):
        return RealEmbeddingClient()
    return FakeEmbeddingClient()
