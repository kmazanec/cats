"""Unit tests for the CSRF token primitives. The middleware + dependency
are exercised by the integration tests; here we cover the pure-function
behavior."""

from __future__ import annotations

import pytest

from cats.security.crypto import decrypt, encrypt
from cats.security.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    generate_token,
)


def test_generate_token_is_urlsafe_and_long_enough() -> None:
    t = generate_token()
    assert len(t) >= 40  # 32 bytes base64 ~ 43 chars
    # urlsafe alphabet: A-Z a-z 0-9 - _
    assert all(c.isalnum() or c in "-_" for c in t)


def test_tokens_are_unique() -> None:
    seen = {generate_token() for _ in range(100)}
    assert len(seen) == 100


def test_csrf_constants_match_clients() -> None:
    # Sanity: the names client code (HTMX hx-headers, form fields) is
    # written against don't drift silently.
    assert CSRF_COOKIE_NAME == "cats_csrf"
    assert CSRF_FORM_FIELD == "csrf_token"
    assert CSRF_HEADER_NAME == "X-CSRF-Token"


def test_encrypt_round_trip() -> None:
    plain = "PHPSESSID=abcd1234"
    token = encrypt(plain)
    assert token != plain
    assert decrypt(token) == plain


def test_encrypt_empty_returns_empty() -> None:
    assert encrypt("") == ""
    assert decrypt("") == ""


def test_decrypt_garbage_raises() -> None:
    with pytest.raises(ValueError):
        decrypt("not-a-valid-fernet-token")
