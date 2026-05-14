"""Unit coverage for ``fire_kickoff_briefing`` — the per-Run briefing
kickoff that harvests the OpenEMR conversationId before any attack
fires. Side effects are routed through fakes so the test runs without
a target or DB."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from cats.agents.red_team import executor as executor_mod
from cats.agents.red_team.executor import KickoffResult, fire_kickoff_briefing
from cats.graph.state import CampaignState
from cats.target.contracts import TargetCallResult


class _FakeSession:
    """Records every record_kickoff call so tests can assert."""

    captured_record: dict[str, Any] | None = None

    async def execute(self, *_a: Any, **_k: Any) -> Any:
        return None

    async def commit(self) -> None:
        return None


@pytest.fixture
def patched_executor(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub the executor's hydrate + persistence dependencies.

    - `_hydrate_target` returns a CampaignState with a placeholder target.
    - `record_kickoff` is replaced with a recorder so we can assert on
      the args without actually writing.
    - `TargetClient.attack` is stubbed at the executor module level so
      we control the SSE result the kickoff sees.
    """
    project_id = uuid4()
    pv_id = uuid4()
    state = CampaignState(
        run_id=uuid4(),
        campaign_id=uuid4(),
        project_version_id=pv_id,
        project_id=project_id,
        target_base_url="https://target.example",
        target_kind="copilot_proxy",
        target_username="u",
        target_password="p",
        target_bearer_token="",
    )

    async def _fake_hydrate(_session: Any, _pv: Any) -> CampaignState:
        return state

    monkeypatch.setattr(executor_mod, "_hydrate_target", _fake_hydrate)

    record_calls: list[dict[str, Any]] = []

    async def _record(*_a: Any, **kwargs: Any) -> Any:
        record_calls.append(dict(kwargs))
        return uuid4()

    monkeypatch.setattr(executor_mod, "record_kickoff", _record)

    return {"state": state, "record_calls": record_calls}


def _install_attack_result(monkeypatch: pytest.MonkeyPatch, result: TargetCallResult) -> None:
    class _FakeClient:
        def __init__(self, **_k: Any) -> None:
            pass

        async def attack(self, _envelope: Any) -> TargetCallResult:
            return result

    monkeypatch.setattr(executor_mod, "TargetClient", _FakeClient)


@pytest.mark.asyncio
async def test_kickoff_happy_path(
    patched_executor: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_attack_result(
        monkeypatch,
        TargetCallResult(
            text='event: meta\ndata: {"type":"meta","conversationId":"conv-abc"}\n\n',
            status_code=200,
            latency_ms=22_500,
            raw_body="",
            assigned_conversation_id="conv-abc",
            stream_shape={"event_counts": {"meta": 1}},
        ),
    )
    session = _FakeSession()
    result = await fire_kickoff_briefing(
        session,  # type: ignore[arg-type]
        run_id=patched_executor["state"].run_id,
        project_version_id=patched_executor["state"].project_version_id,
    )
    assert isinstance(result, KickoffResult)
    assert result.conversation_id == "conv-abc"
    assert result.target_status_code == 200
    assert result.target_latency_ms == 22_500
    assert result.error is None
    # One record_kickoff invocation, with the harvested conv id.
    assert len(patched_executor["record_calls"]) == 1
    rec = patched_executor["record_calls"][0]
    assert rec["conversation_id"] == "conv-abc"
    assert rec["target_status_code"] == 200
    assert rec["target_latency_ms"] == 22_500
    assert rec["error"] is None


@pytest.mark.asyncio
async def test_kickoff_records_failure_when_target_returns_no_conversation_id(
    patched_executor: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_attack_result(
        monkeypatch,
        TargetCallResult(
            text="",
            status_code=502,
            latency_ms=120,
            raw_body="upstream gone",
            error="agent.php upstream rejected: 502",
            assigned_conversation_id=None,
        ),
    )
    session = _FakeSession()
    result = await fire_kickoff_briefing(
        session,  # type: ignore[arg-type]
        run_id=patched_executor["state"].run_id,
        project_version_id=patched_executor["state"].project_version_id,
    )
    assert result.conversation_id is None
    assert result.target_status_code == 502
    assert result.error == "agent.php upstream rejected: 502"
    # The kickoff_turns row is still recorded so forensics show what
    # happened — caller decides how to react.
    assert len(patched_executor["record_calls"]) == 1
    rec = patched_executor["record_calls"][0]
    assert rec["conversation_id"] is None
    assert rec["error"] == "agent.php upstream rejected: 502"


@pytest.mark.asyncio
async def test_kickoff_handles_client_exception_without_raising(
    patched_executor: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _ExplodingClient:
        def __init__(self, **_k: Any) -> None:
            pass

        async def attack(self, _envelope: Any) -> TargetCallResult:
            raise RuntimeError("boom")

    monkeypatch.setattr(executor_mod, "TargetClient", _ExplodingClient)

    session = _FakeSession()
    result = await fire_kickoff_briefing(
        session,  # type: ignore[arg-type]
        run_id=patched_executor["state"].run_id,
        project_version_id=patched_executor["state"].project_version_id,
    )
    # Exception is swallowed, recorded as an error on the result + row.
    assert result.conversation_id is None
    assert result.error is not None
    assert "boom" in result.error
    assert len(patched_executor["record_calls"]) == 1
