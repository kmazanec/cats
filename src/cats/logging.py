"""structlog configuration + LangSmith environment plumbing."""

from __future__ import annotations

import logging
import os
import sys
import warnings

import structlog

from cats.config import settings

# R3: silence a langchain-core PendingDeprecationWarning fired at
# `langgraph.checkpoint.serde.jsonplus` import time. The Reviver() it
# constructs takes its default `allowed_objects` — no hook to override
# from caller code. R2 retro asked R3 to pin this; suppression is the
# only available lever until the upstream default flips.
warnings.filterwarnings(
    "ignore",
    message=".*allowed_objects.*",
    category=DeprecationWarning,
)
warnings.filterwarnings(
    "ignore",
    message=".*allowed_objects.*",
    category=PendingDeprecationWarning,
)


def configure_logging() -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=settings.log_level.upper(),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    if settings.langsmith_tracing and settings.langsmith_api_key:
        os.environ.setdefault("LANGSMITH_TRACING", "true")
        os.environ.setdefault("LANGSMITH_API_KEY", settings.langsmith_api_key)
        os.environ.setdefault("LANGSMITH_PROJECT", settings.langsmith_project)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
