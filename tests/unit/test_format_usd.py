from __future__ import annotations

from cats.agents.common import format_usd


def test_format_positive_dollars_and_cents() -> None:
    assert format_usd(1234) == "$12.34"


def test_format_zero_cents() -> None:
    assert format_usd(0) == "$0.00"


def test_format_negative_cents() -> None:
    assert format_usd(-100) == "-$1.00"


def test_format_exactly_one_dollar() -> None:
    assert format_usd(100) == "$1.00"


def test_format_exactly_one_cent() -> None:
    assert format_usd(1) == "$0.01"


def test_format_negative_one_cent() -> None:
    assert format_usd(-1) == "-$0.01"


def test_format_negative_dollars_and_cents() -> None:
    assert format_usd(-1234) == "-$12.34"


def test_format_large_cents() -> None:
    assert format_usd(1_000_000_00) == "$1000000.00"


def test_format_single_digit_cents() -> None:
    assert format_usd(9) == "$0.09"
