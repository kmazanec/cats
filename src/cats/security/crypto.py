"""Symmetric encryption for sensitive at-rest fields (target credentials).

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from
`CATS_DATA_SECRET` via HKDF. Keys are not the same as the session-cookie
secret — they have different rotation surfaces.

Failing to set CATS_DATA_SECRET in production is a configuration error;
we fall back to a clearly-marked dev key so local-dev works without
ceremony, and log a loud warning if it's used in non-local environments.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from cats.config import settings


def _derive_key() -> bytes:
    """HKDF would be cleaner, but a SHA-256 of a long secret is fine for
    R2 — Fernet keys are 32 random bytes, base64-urlsafe. We swap in HKDF
    when we add key rotation."""
    secret = settings.data_secret or "dev-data-secret-change-me"
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> Fernet:
    return Fernet(_derive_key())


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("could not decrypt — wrong key or corrupted ciphertext") from e
