"""Stub auth dependency. Real impl gates by role
(viewer|operator|senior_operator|admin) per W3_ARCHITECTURE §3.1."""

from __future__ import annotations

from typing import Literal

Role = Literal["viewer", "operator", "senior_operator", "admin"]


class Principal:
    def __init__(self, *, user: str = "dev", role: Role = "admin") -> None:
        self.user = user
        self.role = role


def current_principal() -> Principal:
    """Scaffold stub. Replace with real auth (header / cookie / OIDC)."""
    return Principal()
