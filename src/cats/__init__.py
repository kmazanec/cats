"""CATS — Copilot Automated Tactical Security."""

import warnings

# R3: silence a langchain-core PendingDeprecationWarning fired at
# `langgraph.checkpoint.serde.jsonplus` module-import time. The Reviver()
# it constructs accepts its default `allowed_objects` — no hook from
# caller code. R2 retro asked R3 to pin this; suppression here (before
# any langgraph import) is the only available lever until upstream
# flips the default. Applies to runtime + tests.
#
# Filter by category (resilient to message wording changes); category
# import is wrapped because langchain_core's package layout shifts
# between minor versions and the worst case here is the warning leaks
# through, not a hard import error.
try:  # pragma: no cover — defensive import for transitive dep version skew
    from langchain_core._api.deprecation import LangChainPendingDeprecationWarning

    warnings.filterwarnings("ignore", category=LangChainPendingDeprecationWarning)
except Exception:
    warnings.filterwarnings("ignore", message=r".*allowed_objects.*")

__version__ = "0.1.0"
