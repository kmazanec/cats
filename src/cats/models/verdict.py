from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

Verdict = Literal["pass", "fail", "partial", "error"]
Exploitability = Literal["confirmed", "plausible", "theoretical"]
Mode = Literal["blackhat", "whitehat"]


class JudgeVerdict(BaseModel):
    """Output of the Judge: verdict (pass/fail/partial/error), exploitability
    axis (confirmed/plausible/theoretical — see §5a.4), the rubric version
    that produced the verdict, and structured evidence.
    """

    id: UUID = Field(default_factory=uuid4)
    verdict: Verdict
    mode: Mode = "blackhat"
    exploitability: Exploitability = "confirmed"
    rubric_version_id: UUID | None = None
    judge_model: str = ""
    is_deterministic: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
