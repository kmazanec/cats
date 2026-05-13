"""R3 — DI factory accessors on ``cats.config``."""

from __future__ import annotations

import pytest

from cats.config import (
    Settings,
    get_settings,
    reset_settings_cache,
    set_settings_for_test,
    settings,
)


def test_get_settings_returns_a_singleton_until_cache_reset() -> None:
    """``get_settings()`` returns the same object on repeat calls.
    The module-level ``settings`` is bound at import time; after
    :func:`reset_settings_cache`, ``get_settings()`` rebuilds and the
    module symbol becomes the *previous* generation. Code that wants
    fresh-after-reset must use ``get_settings()``, not ``settings``."""
    a = get_settings()
    b = get_settings()
    assert a is b
    # The module-level singleton was bound at import; under normal
    # operation it equals get_settings(). Integration conftest calls
    # `reset_settings_cache()` which intentionally diverges them — the
    # test in `tests/unit/` runs alongside, so we only assert the
    # invariant get_settings() == get_settings(), not that it equals
    # `settings`.
    _ = settings  # imported above; keep the name in scope for the docstring


def test_set_settings_for_test_mutates_singleton_visible_to_all_holders() -> None:
    """Mutating via the helper must be visible to every subsequent
    ``get_settings()`` caller. We assert through ``get_settings()`` only
    (not the module-level ``settings`` symbol) because integration
    conftest may have called ``reset_settings_cache()`` before this
    test, in which case ``settings`` is the previous-generation
    singleton and ``get_settings()`` returns the live one."""
    set_settings_for_test(openrouter_api_key="sk-or-r3-test")
    assert get_settings().openrouter_api_key == "sk-or-r3-test"
    # Restore so we don't leak across tests.
    set_settings_for_test(openrouter_api_key="")
    assert get_settings().openrouter_api_key == ""


def test_set_settings_for_test_rejects_unknown_field() -> None:
    with pytest.raises(AttributeError):
        set_settings_for_test(not_a_real_field="x")


def test_reset_settings_cache_rebuilds_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-from-env")
    reset_settings_cache()
    fresh = get_settings()
    assert fresh.openrouter_api_key == "sk-from-env"
    # Module-level `settings` was bound at import; it is the *previous*
    # singleton, not the rebuilt one. Code that uses `get_settings()` picks
    # up the new singleton; code that captured `settings` at import time
    # does not. Documented in the factory module's docstring.
    reset_settings_cache()


def test_settings_type_is_pydantic_settings() -> None:
    assert isinstance(get_settings(), Settings)
