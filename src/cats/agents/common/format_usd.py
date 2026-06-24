"""Pure helper to format an integer cent count as a US dollar string.

This module uses only integer arithmetic so that the formatting is exact;
floating-point rounding is never introduced.
"""

from __future__ import annotations


def format_usd(cents: int) -> str:
    """Return a US dollar string for *cents* (e.g. 1234 → ``"$12.34"``).

    Negative *cents* produces a leading minus sign before the dollar sign
    (``-100`` → ``"-$1.00"``).  Zero cents produces ``"$0.00"``.

    The implementation avoids floating-point arithmetic; the result is
    always exact.
    """
    sign = "-" if cents < 0 else ""
    absolute = -cents if cents < 0 else cents
    dollars = absolute // 100
    remainder = absolute % 100
    return f"{sign}${dollars}.{remainder:02d}"
