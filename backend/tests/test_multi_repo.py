"""One installation, several repositories: one team each; scans and installs run concurrently."""

from __future__ import annotations

import asyncio
import copy
import re

import httpx
import pytest
from sqlmodel import select

from app.db import session_scope
from app.models import Developer, PushEvent, Repository, Team
from app.pipeline import handle_installation_event, job_from_push, run_scan
from tests.conftest import FakeGitHub
from tests.test_pipeline import SHA_A, SHA_B, SHA_C, _deterministic, push_payload, seed_commits


@pytest.fixture()
def gh(fake_github: FakeGitHub) -> FakeGitHub:
    return seed_commits(fake_github)


def _repo_push(repo_id: int, name: str, before: str, after: str, delivery: str):
    payload = copy.deepcopy(push_payload(before, after, f"push to {name}"))
    payload["repository"].update(id=repo_id, name=name, full_name=f"acme/{name}")
    return job_from_push(payload, delivery)


def _any_repo(gh: FakeGitHub) -> httpx.MockTransport:
    """Serve every acme/* repository from the fake's single repository."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url.copy_with(path=re.sub(r"^/repos/acme/[^/]+", "/repos/acme/api",
                                                request.url.path))
        return gh.handler(httpx.Request(request.method, url, headers=request.headers,
                                        content=request.content))
    return httpx.MockTransport(handler)


async def test_concurrent_pushes_to_several_repos(db: None, gh: FakeGitHub) -> None:
    transport = _any_repo(gh)
    repos = [(600 + i, f"svc{i}") for i in range(4)]
    jobs = [_repo_push(rid, name, SHA_A, SHA_B, f"d-{rid}") for rid, name in repos]
    install = handle_installation_event("installation", {
        "action": "created",
        "installation": {"id": 77, "account": {"login": "acme", "id": 1,
                                               "type": "Organization"}},
        "repositories": [{"id": rid, "name": n, "full_name": f"acme/{n}"} for rid, n in repos],
    }, transport=transport)
    results = await asyncio.gather(
        install, *(run_scan(j, gh_transport=transport, scanner=_deterministic())
                   for j in jobs), return_exceptions=True)
    assert not [r for r in results if isinstance(r, BaseException)], results
    assert all(r is not None for r in results[1:])

    # a second round on every repo: the shared developer row must count every push
    again = [_repo_push(rid, name, SHA_B, SHA_C, f"e-{rid}") for rid, name in repos]
    results = await asyncio.gather(*(run_scan(j, gh_transport=transport,
                                              scanner=_deterministic()) for j in again),
                                   return_exceptions=True)
    assert not [r for r in results if isinstance(r, BaseException)], results

    async with session_scope() as s:
        teams = (await s.exec(select(Team).order_by(Team.github_repo_id))).all()
        assert [(t.name, t.slug, t.github_repo_id) for t in teams] == [
            (name, name, rid) for rid, name in repos]  # one team per repository
        assert len((await s.exec(select(Repository))).all()) == len(repos)
        assert len((await s.exec(select(PushEvent))).all()) == 2 * len(repos)
        devs = (await s.exec(select(Developer))).all()
        assert sorted(d.team_id for d in devs) == sorted(t.id for t in teams)
        assert all(d.total_pushes == 2 for d in devs)


async def test_migration_splits_a_merged_team(db: None, gh: FakeGitHub) -> None:
    """A database from before per-repo teams: one team per installation, repos merged."""
    from sqlmodel import col, delete

    from app.migrations import split_multi_repo_teams
    from app.models import ScoreSnapshot, TeamIntegration

    transport = _any_repo(gh)
    repos = [(700, "alpha"), (701, "beta")]
    for rid, name in repos:
        for before, after, d in ((SHA_A, SHA_B, "x"), (SHA_B, SHA_C, "y")):
            await run_scan(_repo_push(rid, name, before, after, f"{d}-{rid}"),
                           gh_transport=transport, scanner=_deterministic())

    def snapshot(devs: list[Developer]) -> dict[str, tuple]:
        return {next(n for r, n in repos if r == team_repo[d.team_id]):
                (d.total_pushes, d.faulty_pushes, d.security_score, d.composite_score,
                 d.clean_streak) for d in devs}

    async with session_scope() as s:
        teams = (await s.exec(select(Team))).all()
        team_repo = {t.id: t.github_repo_id for t in teams}
        expected = snapshot((await s.exec(select(Developer))).all())
        keep, gone = sorted(teams, key=lambda t: t.github_repo_id)
        keep_dev = (await s.exec(select(Developer).where(Developer.team_id == keep.id))).one()
        gone_dev = (await s.exec(select(Developer).where(Developer.team_id == gone.id))).one()
        # fold the second repository back into the first team, as the old code stored it
        for model in (Repository, PushEvent, ScoreSnapshot):
            for row in (await s.exec(select(model).where(model.team_id == gone.id))).all():
                row.team_id = keep.id
                if hasattr(row, "developer_id"):
                    row.developer_id = keep_dev.id
                s.add(row)
        await s.flush()
        await s.exec(delete(Developer).where(col(Developer.id) == gone_dev.id))
        await s.exec(delete(Team).where(col(Team.id) == gone.id))
        keep.name, keep.slug, keep.github_repo_id = "acme", "acme", None
        keep_dev.total_pushes = 4  # merged aggregates
        s.add_all([keep, keep_dev, TeamIntegration(team_id=keep.id,
                                                   discord_webhook_url="https://d.test/x")])

    async with session_scope() as s:
        await split_multi_repo_teams(s)
    async with session_scope() as s:  # idempotent
        await split_multi_repo_teams(s)

    async with session_scope() as s:
        teams = (await s.exec(select(Team).order_by(Team.github_repo_id))).all()
        assert [(t.name, t.slug, t.github_repo_id) for t in teams] == [
            ("alpha", "acme", 700), ("beta", "beta", 701)]  # the old URL keeps working
        team_repo = {t.id: t.github_repo_id for t in teams}
        assert snapshot((await s.exec(select(Developer))).all()) == expected
        for t in teams:
            repo = (await s.exec(select(Repository).where(Repository.team_id == t.id))).one()
            assert repo.github_repo_id == t.github_repo_id
            pushes = (await s.exec(select(PushEvent).where(PushEvent.team_id == t.id))).all()
            assert len(pushes) == 2 and {p.repository_id for p in pushes} == {repo.id}
            dev = (await s.exec(select(Developer).where(Developer.team_id == t.id))).one()
            assert {p.developer_id for p in pushes} == {dev.id}
            snaps = (await s.exec(select(ScoreSnapshot).where(
                ScoreSnapshot.team_id == t.id))).all()
            assert len(snaps) == 2 and {x.developer_id for x in snaps} == {dev.id}
            assert (await s.exec(select(TeamIntegration).where(
                TeamIntegration.team_id == t.id))).one().discord_webhook_url
