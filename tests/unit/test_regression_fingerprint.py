"""Unit tests for the gate-3 fingerprint primitives + the fake
embedding client. Pure math / deterministic stub; no infra required."""

from __future__ import annotations

import math

import pytest

from cats.llm.embeddings import FakeEmbeddingClient
from cats.regression.fingerprint import cosine_similarity, fingerprint_matches


class TestCosineSimilarity:
    def test_identical_vectors_score_one(self) -> None:
        v = [1.0, 2.0, 3.0]
        sim = cosine_similarity(v, v)
        assert sim is not None
        assert math.isclose(sim, 1.0, rel_tol=1e-9)

    def test_orthogonal_vectors_score_zero(self) -> None:
        sim = cosine_similarity([1.0, 0.0], [0.0, 1.0])
        assert sim == pytest.approx(0.0)

    def test_opposite_vectors_score_minus_one(self) -> None:
        sim = cosine_similarity([1.0, 0.0], [-1.0, 0.0])
        assert sim == pytest.approx(-1.0)

    def test_empty_inputs_return_none(self) -> None:
        assert cosine_similarity([], [1.0, 2.0]) is None
        assert cosine_similarity([1.0], []) is None
        assert cosine_similarity(None, [1.0]) is None
        assert cosine_similarity([1.0], None) is None

    def test_length_mismatch_returns_none(self) -> None:
        assert cosine_similarity([1.0, 2.0], [1.0, 2.0, 3.0]) is None

    def test_zero_vector_returns_none(self) -> None:
        assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) is None


class TestFingerprintMatches:
    def test_match_at_or_above_threshold_is_true(self) -> None:
        v = [1.0, 0.0]
        assert fingerprint_matches(v, v, threshold=0.75) is True

    def test_below_threshold_is_false(self) -> None:
        # cosine([1,0], [0,1]) = 0.0 < threshold
        assert fingerprint_matches([1.0, 0.0], [0.0, 1.0], threshold=0.75) is False

    def test_missing_exemplar_is_unclear(self) -> None:
        # A RegressionCase without a captured exemplar means gate-3 cannot
        # score — runner must route to needs_review, not auto-pass.
        assert fingerprint_matches([1.0, 0.0], None, threshold=0.75) is None
        assert fingerprint_matches([1.0, 0.0], [], threshold=0.75) is None


class TestFakeEmbeddingClient:
    @pytest.mark.asyncio
    async def test_identical_inputs_produce_identical_vectors(self) -> None:
        c = FakeEmbeddingClient()
        v1 = await c.embed("hello world")
        v2 = await c.embed("hello world")
        assert v1 == v2
        # cosine with itself = 1.0
        sim = cosine_similarity(v1, v2)
        assert sim is not None and math.isclose(sim, 1.0, rel_tol=1e-9)

    @pytest.mark.asyncio
    async def test_different_inputs_score_below_threshold(self) -> None:
        c = FakeEmbeddingClient()
        v1 = await c.embed("the model declined the request")
        v2 = await c.embed("here is the patient's chart you asked for")
        sim = cosine_similarity(v1, v2)
        # Hash-derived vectors decorrelate hard; well below 0.75.
        assert sim is not None and sim < 0.5

    @pytest.mark.asyncio
    async def test_aliases_force_equality(self) -> None:
        # Tests can stage "the model refuses differently but the
        # semantic class is the same" by aliasing two inputs.
        c = FakeEmbeddingClient(aliases={"new refusal text": "anchor"})
        v_anchor = await c.embed("anchor")
        v_alias = await c.embed("new refusal text")
        assert v_anchor == v_alias

    @pytest.mark.asyncio
    async def test_empty_input_returns_empty_vector(self) -> None:
        c = FakeEmbeddingClient()
        assert await c.embed("") == []

    @pytest.mark.asyncio
    async def test_call_log_tracks_inputs(self) -> None:
        c = FakeEmbeddingClient()
        await c.embed("a")
        await c.embed("b")
        assert c.call_log == ["a", "b"]
