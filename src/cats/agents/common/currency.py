"""Pure currency-formatting helpers.

Decoupled from LLM cost accounting so they can be used anywhere without
importing graph state or LLM types.
"""

from __future__ import annotations


def format_usd(cents: int) -> str:
    """Format an integer number of cents as a US dollar string.

    Args:
        cents: The amount in cents (e.g. 1234 for $12.34).

    Returns:
        A string like ``"$12.34"``. Negative values produce a leading
        minus sign before the dollar sign (e.g. ``"-$5.00"``).

    Examples:
        >>> format_usd(1234)
        '$12.34'
        >>> format_usd(0)
        '$0.00'
        >>> format_usd(-500)
        '-$5.00'
        >>> format_usd(5)
        '$0.05'
    """
    sign = "-" if cents < 0 else ""
    absolute = abs(cents)
    dollars, remainder = divmod(absolute, 100)
    return f"{sign}${dollars}.{remainder:02d}"
