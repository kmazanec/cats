"""Unit tests for the bcrypt helpers, role rank, and signed session token."""

from __future__ import annotations

from uuid import uuid4

import pytest

from cats.api.auth import (
    ROLE_RANK,
    Principal,
    hash_password,
    issue_session_token,
    read_session_token,
    verify_password,
)


def test_hash_password_round_trips() -> None:
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong", h) is False


def test_hash_password_rejects_short() -> None:
    with pytest.raises(ValueError):
        hash_password("")
    with pytest.raises(ValueError):
        hash_password("short")


def test_hash_password_accepts_floor() -> None:
    h = hash_password("12345678")
    assert verify_password("12345678", h) is True


def test_verify_password_handles_garbage() -> None:
    assert verify_password("anything", "not-a-bcrypt-string") is False
    assert verify_password("", "anything") is False


def test_role_rank_strict_ordering() -> None:
    assert ROLE_RANK["viewer"] < ROLE_RANK["operator"]
    assert ROLE_RANK["operator"] < ROLE_RANK["senior_operator"]
    assert ROLE_RANK["senior_operator"] < ROLE_RANK["admin"]


def test_principal_has_role() -> None:
    p_admin = Principal(user_id=uuid4(), email="a@b", role="admin")
    p_viewer = Principal(user_id=uuid4(), email="v@b", role="viewer")
    p_operator = Principal(user_id=uuid4(), email="o@b", role="operator")

    assert p_admin.has_role("viewer") is True
    assert p_admin.has_role("admin") is True
    assert p_viewer.has_role("operator") is False
    assert p_operator.has_role("senior_operator") is False
    assert p_operator.has_role("operator") is True


def test_session_token_round_trip() -> None:
    user_id = uuid4()
    tok = issue_session_token(user_id)
    assert read_session_token(tok) == user_id


def test_session_token_rejects_garbage() -> None:
    assert read_session_token("garbage") is None
    assert read_session_token("") is None
