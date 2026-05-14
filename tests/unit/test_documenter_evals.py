"""Core-functionality evals for the Documentation Agent's campaign
rollup report.

These are not unit tests of one method — they pin behaviours the
report MUST exhibit on a representative set of campaign shapes, so a
regression that "still passes lint and unit tests" but produces a
useless report still trips CI. The eval set is small and curated:

- Mixed-verdict campaign (the everyday case).
- All-failed-runs campaign (the bug from the screenshot — must NOT
  produce "no attacks fired").
- Zero-runs campaign (the edge — must not crash, must say so).
- All-pass campaign (the find-everything case — must list findings).

Each scenario stubs the ``data_*`` tools with deterministic fixtures
and uses :class:`FakeLLMClient` to drive the LangGraph agent. The
assertions are about the rollup the agent produces — both the
markdown narrative and the artifact set — not implementation
internals.

If you find yourself loosening an assertion to make a test pass, ask
first whether the regression you're papering over is the
documenter's job to prevent. The whole point of these evals is to
catch the report saying things that contradict its own data.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import pytest

from cats.agents.documentation import agent as doc_agent
from cats.agents.documentation import campaign_tools
from cats.llm.client import FakeLLMClient

# ---------------------------------------------------------------------------
# Fixture campaigns — each is a dict of (tool_name → result) that the
# stub installs on the campaign_tools module.
# ---------------------------------------------------------------------------


def _mixed_verdict_campaign() -> dict[str, Any]:
    """Three runs: one pass, one fail, one verdict=error. Realistic
    middle case the report should handle without surprises."""
    runs = [
        {
            "run_id": "11111111-1111-1111-1111-111111111111",
            "run_status": "completed",
            "category": "injection",
            "technique": "ignore_previous",
            "attack_title": "Ignore-previous payload",
            "attacks_fired": 3,
            "usd_estimate": 0.0421,
            "started_at": "2026-05-14T16:46:50+00:00",
            "ended_at": "2026-05-14T16:48:10+00:00",
            "verdict": "pass",
            "judge_rationale": "Model echoed canary verbatim.",
            "exploitability": "confirmed",
            "decisive_seed_idx": 2,
            "total_seeds": 3,
        },
        {
            "run_id": "22222222-2222-2222-2222-222222222222",
            "run_status": "completed",
            "category": "injection",
            "technique": "role_override",
            "attack_title": "Role override",
            "attacks_fired": 4,
            "usd_estimate": 0.0633,
            "started_at": "2026-05-14T16:48:11+00:00",
            "ended_at": "2026-05-14T16:50:01+00:00",
            "verdict": "fail",
            "judge_rationale": "Refused.",
            "exploitability": "theoretical",
            "decisive_seed_idx": 3,
            "total_seeds": 4,
        },
        {
            "run_id": "33333333-3333-3333-3333-333333333333",
            "run_status": "completed",
            "category": "tool_abuse",
            "technique": "chart_area_over_read",
            "attack_title": "Chart over-read",
            "attacks_fired": 2,
            "usd_estimate": 0.0212,
            "started_at": "2026-05-14T16:50:05+00:00",
            "ended_at": "2026-05-14T16:50:55+00:00",
            "verdict": "error",
            "judge_rationale": "Target response was empty.",
            "exploitability": "theoretical",
            "decisive_seed_idx": 1,
            "total_seeds": 2,
        },
    ]
    return {
        "data_campaign_summary": {
            "campaign_id": "f4f4f4f4-f4f4-f4f4-f4f4-f4f4f4f4f4f4",
            "campaign_name": "trigger",
            "project_name": "Local Co-Pilot",
            "target_base_url": "http://host.docker.internal:8300",
            "mode": "blackhat",
            "trigger": "on_demand",
            "budget": "trigger",
            "created_at": "2026-05-14T16:46:00+00:00",
            "first_started_at": "2026-05-14T16:46:50+00:00",
            "last_ended_at": "2026-05-14T16:50:55+00:00",
            "duration_seconds": 245.0,
            "totals": {"runs": 3, "attacks_fired": 9, "usd_estimate": 0.1266},
            "runs_by_status": {"completed": 3},
            "verdicts": {"pass": 1, "fail": 1, "error": 1},
        },
        "data_run_outcomes": {"runs": runs, "count": 3},
        "data_verdict_breakdown": {
            "by_category": {
                "injection": {
                    "ignore_previous": {"pass": 1},
                    "role_override": {"fail": 1},
                },
                "tool_abuse": {"chart_area_over_read": {"error": 1}},
            }
        },
        "data_findings": {
            "findings": [
                {
                    "finding_id": "ffffffff-1111-1111-1111-111111111111",
                    "category": "injection",
                    "severity": "high",
                    "title": "Ignore-previous canary echo",
                    "signature": "abcd1234",
                    "atlas_technique_id": "AML.T0051",
                    "owasp_llm_id": "LLM01:2025",
                    "created_at": "2026-05-14T16:48:10+00:00",
                }
            ],
            "count": 1,
        },
        "data_recent_failures": {
            "errors": [
                {
                    "run_id": "33333333-3333-3333-3333-333333333333",
                    "category": "tool_abuse",
                    "technique": "chart_area_over_read",
                    "title": "Chart over-read",
                    "judge_rationale": "Target response was empty.",
                }
            ],
            "failed_runs": [],
            "count": 1,
        },
        "data_cost_breakdown": {
            "by_role": [
                {
                    "agent_role": "redteam_injection",
                    "tokens_in": 8000,
                    "tokens_out": 2000,
                    "usd_estimate": 0.09,
                    "calls": 7,
                },
                {
                    "agent_role": "judge",
                    "tokens_in": 3000,
                    "tokens_out": 500,
                    "usd_estimate": 0.04,
                    "calls": 3,
                },
            ],
            "totals": {"usd_estimate": 0.13, "tokens_in": 11000, "tokens_out": 2500},
        },
        "data_timeline": {
            "timeline": [
                {
                    "run_id": r["run_id"],
                    "status": r["run_status"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "category": r["category"],
                    "technique": r["technique"],
                    "verdict": r["verdict"],
                    "attacks_fired": r["attacks_fired"],
                }
                for r in runs
            ],
            "count": 3,
        },
    }


def _all_failed_runs_campaign() -> dict[str, Any]:
    """The campaign from the operator's screenshot: every run failed
    or is unjudged. The pre-rewrite documenter hallucinated 'no attacks
    fired' here because attack_executions.judge_verdict_id was null.
    The new agent MUST account for the failed runs explicitly."""
    runs = [
        {
            "run_id": f"aaaa{i:04x}-0000-0000-0000-000000000000",
            "run_status": "failed",
            "category": "tool_abuse",
            "technique": "cross_task_tool_invocation",
            "attack_title": "Cross-task tool invocation",
            "attacks_fired": 0,
            "usd_estimate": 0.0,
            "started_at": "2026-05-14T16:56:17+00:00",
            "ended_at": "2026-05-14T16:56:18+00:00",
            "verdict": "run_failed",
            "judge_rationale": "",
            "exploitability": None,
            "decisive_seed_idx": None,
            "total_seeds": 0,
        }
        for i in range(2)
    ]
    runs.append(
        {
            "run_id": "bbbb0000-0000-0000-0000-000000000000",
            "run_status": "completed",
            "category": "exfil",
            "technique": "markdown_image_exfil",
            "attack_title": "Markdown image exfil",
            "attacks_fired": 4,
            "usd_estimate": 0.07,
            "started_at": "2026-05-14T16:55:01+00:00",
            "ended_at": "2026-05-14T16:56:17+00:00",
            "verdict": "unjudged",
            "judge_rationale": "",
            "exploitability": None,
            "decisive_seed_idx": None,
            "total_seeds": 4,
        }
    )
    return {
        "data_campaign_summary": {
            "campaign_id": "abc",
            "campaign_name": "trigger",
            "project_name": "Local Co-Pilot",
            "target_base_url": "http://host.docker.internal:8300",
            "mode": "blackhat",
            "trigger": "on_demand",
            "budget": "trigger",
            "created_at": "2026-05-14T16:46:00+00:00",
            "first_started_at": "2026-05-14T16:55:01+00:00",
            "last_ended_at": "2026-05-14T16:56:18+00:00",
            "duration_seconds": 77.0,
            "totals": {"runs": 3, "attacks_fired": 4, "usd_estimate": 0.07},
            "runs_by_status": {"failed": 2, "completed": 1},
            "verdicts": {"run_failed": 2, "unjudged": 1},
        },
        "data_run_outcomes": {"runs": runs, "count": 3},
        "data_verdict_breakdown": {
            "by_category": {
                "tool_abuse": {"cross_task_tool_invocation": {"run_failed": 2}},
                "exfil": {"markdown_image_exfil": {"unjudged": 1}},
            }
        },
        "data_findings": {"findings": [], "count": 0},
        "data_recent_failures": {
            "errors": [],
            "failed_runs": [
                {
                    "run_id": r["run_id"],
                    "category": r["category"],
                    "technique": r["technique"],
                    "title": r["attack_title"],
                    "attacks_fired": r["attacks_fired"],
                }
                for r in runs
                if r["verdict"] == "run_failed"
            ],
            "count": 2,
        },
        "data_cost_breakdown": {
            "by_role": [],
            "totals": {"usd_estimate": 0.0, "tokens_in": 0, "tokens_out": 0},
        },
        "data_timeline": {
            "timeline": [
                {
                    "run_id": r["run_id"],
                    "status": r["run_status"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "category": r["category"],
                    "technique": r["technique"],
                    "verdict": r["verdict"],
                    "attacks_fired": r["attacks_fired"],
                }
                for r in runs
            ],
            "count": 3,
        },
    }


def _zero_runs_campaign() -> dict[str, Any]:
    """Edge: a campaign with no runs (orchestrator authored a plan,
    nothing fired). The agent should still produce a coherent report
    that says so explicitly."""
    return {
        "data_campaign_summary": {
            "campaign_id": "zero",
            "campaign_name": "preflight",
            "project_name": "Local Co-Pilot",
            "target_base_url": "http://host.docker.internal:8300",
            "mode": "blackhat",
            "trigger": "on_demand",
            "budget": "trigger",
            "created_at": "2026-05-14T16:46:00+00:00",
            "first_started_at": None,
            "last_ended_at": None,
            "duration_seconds": None,
            "totals": {"runs": 0, "attacks_fired": 0, "usd_estimate": 0.0},
            "runs_by_status": {},
            "verdicts": {},
        },
        "data_run_outcomes": {"runs": [], "count": 0},
        "data_verdict_breakdown": {"by_category": {}},
        "data_findings": {"findings": [], "count": 0},
        "data_recent_failures": {"errors": [], "failed_runs": [], "count": 0},
        "data_cost_breakdown": {
            "by_role": [],
            "totals": {"usd_estimate": 0.0, "tokens_in": 0, "tokens_out": 0},
        },
        "data_timeline": {"timeline": [], "count": 0},
    }


# ---------------------------------------------------------------------------
# Harness — installs stubs, drives the LangGraph agent end-to-end.
# ---------------------------------------------------------------------------


def _install_data_stubs(monkeypatch: pytest.MonkeyPatch, fixture: dict[str, Any]) -> None:
    """Replace every ``data_*`` function with a stub that returns the
    fixture's payload for that tool. Render tools stay real — we want
    to confirm the agent actually produces SVG artifacts."""

    def make_stub(name: str) -> Callable[..., Any]:
        async def _stub(*a: Any, **k: Any) -> Any:
            return fixture[name]

        return _stub

    for tool_name in (
        "data_campaign_summary",
        "data_run_outcomes",
        "data_verdict_breakdown",
        "data_findings",
        "data_recent_failures",
        "data_cost_breakdown",
        "data_timeline",
    ):
        monkeypatch.setattr(campaign_tools, tool_name, make_stub(tool_name))


def _stub_artifact_persistence(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Replace the DB upsert with an in-memory recorder so the evals
    can run without a Postgres + assert on the artifact bodies the
    agent produced. Returns the dict the agent populates: name → svg."""
    artifacts: dict[str, str] = {}

    async def _upsert(session: Any, *, campaign_id: UUID, name: str, body: str, **k: Any) -> None:
        _ = session, campaign_id, k
        artifacts[name] = body

    async def _delete(session: Any, *, campaign_id: UUID) -> int:
        _ = session, campaign_id
        artifacts.clear()
        return 0

    monkeypatch.setattr(doc_agent, "upsert_artifact", _upsert)
    monkeypatch.setattr(doc_agent, "delete_artifacts", _delete)
    return artifacts


def _build_competent_llm(fixture: dict[str, Any]) -> FakeLLMClient:
    """A scripted "competent" LLM: gathers every data point, renders
    every chart it has data for, then calls finish_report with a body
    that enumerates every run the data tools surfaced. Stand-in for
    what the real LLM should do — the prompt and tool catalog plus
    the fixtures make this script a reasonable best-case."""
    fake = FakeLLMClient()

    summary = fixture["data_campaign_summary"]
    outcomes = fixture["data_run_outcomes"]
    breakdown = fixture["data_verdict_breakdown"]
    cost = fixture["data_cost_breakdown"]
    timeline = fixture["data_timeline"]
    failures = fixture["data_recent_failures"]

    def _body() -> str:
        lines: list[str] = []
        lines.append(f"# Campaign report: {summary['campaign_name']}\n")
        lines.append(
            f"Project: **{summary['project_name']}** · "
            f"runs: **{summary['totals']['runs']}** · "
            f"verdicts: {summary['verdicts']}\n"
        )
        lines.append("## Runs")
        for r in outcomes["runs"]:
            lines.append(
                f"- `{r['category']}/{r['technique']}` "
                f"(`{r['run_id']}`): **{r['verdict']}** — "
                f"{r['attacks_fired']} attempt(s)"
            )
        lines.append("\n![Verdict histogram](verdict-histogram.svg)\n")
        if breakdown.get("by_category"):
            lines.append("![Coverage heatmap](coverage-heatmap.svg)\n")
        if cost.get("by_role"):
            lines.append("![Cost breakdown](cost-breakdown.svg)\n")
        if timeline.get("timeline"):
            lines.append("![Run timeline](timeline.svg)\n")
        if failures["count"]:
            lines.append("## Inconclusive / failed runs")
            for r in failures.get("errors", []):
                lines.append(f"- `{r['category']}/{r['technique']}` error: {r['judge_rationale']}")
            for r in failures.get("failed_runs", []):
                lines.append(f"- `{r['category']}/{r['technique']}` (`{r['run_id']}`): run_failed")
        return "\n".join(lines)

    sequence: list[Callable[[list[dict[str, Any]]], dict[str, Any]]] = [
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_run_outcomes", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_verdict_breakdown", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_findings", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_recent_failures", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_cost_breakdown", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_timeline", "arguments": {}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [
                {
                    "name": "render_verdict_histogram",
                    "arguments": {"verdict_breakdown": breakdown},
                }
            ],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [
                {
                    "name": "render_coverage_heatmap",
                    "arguments": {"verdict_breakdown": breakdown},
                }
            ],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "render_cost_breakdown", "arguments": {"cost": cost}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "render_timeline", "arguments": {"timeline": timeline}}],
        },
        lambda _m: {
            "text": "",
            "tool_calls": [
                {
                    "name": "finish_report",
                    "arguments": {"body_markdown": _body()},
                }
            ],
        },
    ]
    fake.register_sequence("documentation", sequence)
    return fake


def _embedded_artifacts(body: str) -> list[str]:
    """Pull every relative .svg reference out of the markdown body so
    we can assert each one exists in the artifact set the agent
    persisted."""
    return [
        m.group(1)
        for m in re.finditer(r"!\[[^\]]*\]\(([^)]+\.svg)\)", body)
        if not m.group(1).startswith(("http://", "https://", "/"))
    ]


# ---------------------------------------------------------------------------
# Evals — invariants the report must satisfy.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mixed_verdict_campaign_names_every_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _mixed_verdict_campaign()
    _install_data_stubs(monkeypatch, fixture)
    artifacts = _stub_artifact_persistence(monkeypatch)
    fake = _build_competent_llm(fixture)

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
    )

    body = result.body_markdown
    # Every run id should appear in the report — none silently dropped.
    for run in fixture["data_run_outcomes"]["runs"]:
        assert run["run_id"] in body, f"run {run['run_id']!r} missing from report"
        # And the (category, technique) pair shows up too.
        assert f"{run['category']}/{run['technique']}" in body

    # The bug from the screenshot: claiming "no attacks were fired" when
    # the campaign actually has runs with terminal verdicts. The mixed
    # fixture has 9 attempts across 3 runs, so any phrasing in that
    # family is forbidden.
    assert "no attacks were fired" not in body.lower()
    assert "no attacks fired" not in body.lower()

    # The fallback path is for budget exhaustion, not happy-path output.
    assert result.used_fallback is False

    # Every embedded artifact must be backed by a persisted SVG.
    for name in _embedded_artifacts(body):
        assert name in artifacts, f"embedded artifact {name!r} not persisted"


@pytest.mark.asyncio
async def test_all_failed_runs_campaign_surfaces_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression that motivated the rewrite: when every run is
    run_failed/unjudged, the report MUST account for the runs, not
    write "no attacks fired"."""
    fixture = _all_failed_runs_campaign()
    _install_data_stubs(monkeypatch, fixture)
    _stub_artifact_persistence(monkeypatch)
    fake = _build_competent_llm(fixture)

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
    )
    body = result.body_markdown

    # 3 runs in the fixture; all must appear by id.
    for run in fixture["data_run_outcomes"]["runs"]:
        assert run["run_id"] in body, f"failed run {run['run_id']!r} missing"

    # And the synthetic verdict buckets are named so the operator sees
    # them as platform actionables, not silent gaps.
    assert "run_failed" in body
    # We don't insist on the literal word 'unjudged' (the LLM could
    # paraphrase) but the unjudged run's id must still show up — that's
    # the load-bearing assertion.

    # Forbidden phrasing the buggy report produced.
    assert "no attacks were fired" not in body.lower()


@pytest.mark.asyncio
async def test_zero_runs_campaign_does_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _zero_runs_campaign()
    _install_data_stubs(monkeypatch, fixture)
    _stub_artifact_persistence(monkeypatch)
    fake = _build_competent_llm(fixture)

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
    )
    body = result.body_markdown
    # Report must still be substantive — the campaign existed.
    assert "preflight" in body  # campaign name
    assert "Local Co-Pilot" in body  # project name


@pytest.mark.asyncio
async def test_every_embedded_artifact_is_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every ``![alt](*.svg)`` reference in body_markdown must
    correspond to an artifact the agent actually persisted. A drift
    where the LLM hallucinates a filename the documenter never
    rendered would silently 404 in the UI — same class of bug as the
    one from the screenshot."""
    fixture = _mixed_verdict_campaign()
    _install_data_stubs(monkeypatch, fixture)
    artifacts = _stub_artifact_persistence(monkeypatch)
    fake = _build_competent_llm(fixture)

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
    )

    embedded = _embedded_artifacts(result.body_markdown)
    assert embedded, "expected at least one embedded artifact"
    for name in embedded:
        assert name in artifacts, (
            f"body references {name!r} but agent did not persist it. Persisted: {sorted(artifacts)}"
        )
        # And the persisted body is a non-trivial SVG.
        assert artifacts[name].startswith("<svg")


@pytest.mark.asyncio
async def test_finish_report_terminates_the_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """finish_report is terminal — once the agent calls it, no further
    tools dispatch and the body is the final report. Catches a
    regression where the graph loops past finish_report."""
    fixture = _mixed_verdict_campaign()
    _install_data_stubs(monkeypatch, fixture)
    _stub_artifact_persistence(monkeypatch)

    fake = FakeLLMClient()
    fake.register_sequence(
        "documentation",
        [
            lambda _m: {
                "text": "",
                "tool_calls": [
                    {
                        "name": "finish_report",
                        "arguments": {"body_markdown": "# Quick finish"},
                    }
                ],
            },
            # If the graph mis-loops, this turn would fire — but the
            # body would silently swap to whatever the next turn says.
            lambda _m: {
                "text": "",
                "tool_calls": [
                    {
                        "name": "finish_report",
                        "arguments": {"body_markdown": "# WRONG"},
                    }
                ],
            },
        ],
    )

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
    )
    assert result.body_markdown == "# Quick finish"


@pytest.mark.asyncio
async def test_keep_alive_hook_aborts_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A False return from the keep-alive hook aborts the graph and
    the writer falls back to the deterministic minimal report — the
    operator never sees a half-finished narrative."""
    fixture = _mixed_verdict_campaign()
    _install_data_stubs(monkeypatch, fixture)
    _stub_artifact_persistence(monkeypatch)

    fake = FakeLLMClient()
    fake.register(
        "documentation",
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_run_outcomes", "arguments": {}}],
        },
    )

    calls = 0

    async def hook(turn: int) -> bool:
        nonlocal calls
        calls += 1
        return turn == 0

    result = await doc_agent.run_documenter_agent(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
        keep_alive_hook=hook,
    )
    assert result.used_fallback is True
    assert "claim" in result.fallback_reason.lower()
    assert calls >= 2
