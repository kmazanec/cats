"""R8 — /regressions list + detail page smoke tests."""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

from cats.db.engine import session_scope


@pytest.mark.asyncio
async def test_regressions_list_empty(client: AsyncClient) -> None:
    # Need an authenticated session for the route. Log in as the seeded admin.
    from tests.integration.conftest import csrf_post

    resp = await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    resp = await client.get("/regressions")
    assert resp.status_code == 200
    assert b"Regressions" in resp.content
    assert b"no regression cases yet" in resp.content


@pytest.mark.asyncio
async def test_regressions_list_with_case(client: AsyncClient) -> None:
    from cats.db.repositories.campaign_repo import create_campaign_and_run
    from cats.db.repositories.project_repo import create_project
    from cats.db.repositories.regression_repo import ensure_regression_case
    from cats.db.repositories.run_repo import upsert_finding
    from cats.security.crypto import encrypt
    from tests.integration.conftest import csrf_post

    async with session_scope() as session:
        project_id = await create_project(
            session,
            name="UI Target",
            base_url="http://fake-openemr.test",
            env="local",
            allow_run_against=True,
            target_kind="copilot_proxy",
            target_username="admin",
            target_password_encrypted=encrypt("pass"),
        )
        _cid, rid, _pvid = await create_campaign_and_run(
            session,
            project_id=project_id,
            name="ui regr",
            category="injection",
        )
        finding_id = await upsert_finding(
            session,
            run_id=rid,
            category="injection",
            signature="sig-ui-1",
            title="ui regression test finding",
            severity="high",
            summary="",
        )
        case_id = await ensure_regression_case(
            session,
            source_finding_id=finding_id,
            canonical_attack_id=uuid4(),
            locked_rubric_version_id=None,
        )

    resp = await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    resp = await client.get("/regressions")
    assert resp.status_code == 200
    assert b"ui regression test finding" in resp.content
    # Case has never been swept; the per-row status reads "never swept".
    assert b"never swept" in resp.content

    detail = await client.get(f"/regressions/{case_id}")
    assert detail.status_code == 200
    assert b"ui regression test finding" in detail.content
    # Detail page calls out the unset exemplar.
    assert b"not yet captured" in detail.content
