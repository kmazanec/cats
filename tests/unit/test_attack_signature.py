from __future__ import annotations

from cats.models.attack import Attack


def test_signature_is_deterministic_over_payload_key_order() -> None:
    a1 = Attack(category="injection", title="t", payload={"a": 1, "b": 2})
    a2 = Attack(category="injection", title="t", payload={"b": 2, "a": 1})
    assert a1.compute_signature() == a2.compute_signature()


def test_signature_changes_with_payload() -> None:
    a1 = Attack(category="injection", title="t", payload={"a": 1})
    a2 = Attack(category="injection", title="t", payload={"a": 2})
    assert a1.compute_signature() != a2.compute_signature()


def test_signature_changes_with_category() -> None:
    a1 = Attack(category="injection", title="t", payload={"a": 1})
    a2 = Attack(category="exfil", title="t", payload={"a": 1})
    assert a1.compute_signature() != a2.compute_signature()
