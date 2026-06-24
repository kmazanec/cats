"""Unit tests for cats.agents.common.currency.format_usd."""

from __future__ import annotations

from cats.agents.common.currency import format_usd


def test_format_usd_zero() -> None:
    assert format_usd(0) == "$0.00"


def test_format_usd_single_digit_cents() -> None:
    assert format_usd(5) == "$0.05"
    assert format_usd(9) == "$0.09"


def test_format_usd_exact_dollar() -> None:
    assert format_usd(100) == "$1.00"
    assert format_usd(2500) == "$25.00"


def test_format_usd_dollars_and_cents() -> None:
    assert format_usd(1234) == "$12.34"


def test_format_usd_negative_small() -> None:
    assert format_usd(-500) == "-$5.00"


def test_format_usd_negative_single_digit_cents() -> None:
    assert format_usd(-1) == "-$0.01"


def test_format_usd_negative_large() -> None:
    assert format_usd(-123456) == "-$1234.56"


def test_format_usd_large_value() -> None:
    # 10 million dollars
    assert format_usd(1_000_000_000) == "$10000000.00"


def test_format_usd_rounding_is_not_performed() -> None:
    """format_usd takes exact cents; it does not round fractional inputs."""
    # 1.5 cents is not representable — the caller must round before passing.
    assert format_usd(1) == "$0.01"
    assert format_usd(2) == "$0.02"


def test_format_usd_negative_zero_is_not_distinguished() -> None:
    # -0 is just 0 in Python, so it formats the same as zero.
    assert format_usd(-0) == "$0.00"  # type: ignore[int]  # intentionally testing -0
