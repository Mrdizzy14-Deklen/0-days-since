"""Deleting a repository on GitHub (or removing it from the App) deletes its page and data."""

from __future__ import annotations

from typing import Any

import pytest
from sqlmodel import select

from app.db import session_scope
from app.models import (
    CodeEdge,
    CodeSymbol,
    Developer,
    Finding,
    PushEvent,
    RepoFile,
    Repository,
    ScoreSnapshot,
    Team,
    TeamIntegration,
)
from app.pipeline import (
    handle_installation_event,
    handle_repository_event,
    job_from_push,
    run_scan,
)
from tests.conftest import FakeGitHub
from tests.test_pipeline import (
    REPO_PAYLOAD,
    SHA_A,
    SHA_B,
    _deterministic,
    push_payload,
    seed_commits,
)

TABLES = (Team, Repository, RepoFile, CodeSymbol, CodeEdge, Developer, PushEvent, Finding,
          ScoreSnapshot, TeamIntegration)


@pytest.fixture()
def gh(fake_github: FakeGitHub) -> FakeGitHub:
    return seed_commits(fake_github)


async def _counts() -> dict[str, int]:
    async with session_scope() as s:
        return {m.__name__: len((await s.exec(select(m))).all()) for m in TABLES}


async def _scanned_team(gh: FakeGitHub) -> None:
    await run_scan(job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0"),
                   gh_transport=gh.transport, scanner=_deterministic())
    await run_scan(job_from_push(push_payload(SHA_A, SHA_B, "Add user lookup"), "d-1"),
                   gh_transport=gh.transport, scanner=_deterministic())
    async with session_scope() as s:
        team = (await s.exec(select(Team))).one()
        s.add(TeamIntegration(team_id=team.id, discord_webhook_url="https://x"))
    counts = await _counts()
    assert all(counts[m] > 0 for m in ("Team", "PushEvent", "Finding", "ScoreSnapshot",
                                         "CodeSymbol", "RepoFile", "Developer"))


async def test_deleted_repository_removes_everything(db: None, gh: FakeGitHub) -> None:
    await _scanned_team(gh)
    payload: dict[str, Any] = {"action": "deleted", "repository": REPO_PAYLOAD,
                               "installation": {"id": 77}}
    assert await handle_repository_event(payload) is True
    assert set((await _counts()).values()) == {0}
    # other repository actions, or unknown repos, change nothing
    assert await handle_repository_event({**payload, "action": "renamed"}) is False
    assert await handle_repository_event(payload) is False


async def test_repo_removed_from_the_app_removes_everything(db: None, gh: FakeGitHub) -> None:
    await _scanned_team(gh)
    await handle_installation_event("installation_repositories", {
        "action": "removed", "installation": {"id": 77, "account": {"login": "acme"}},
        "repositories_removed": [{"id": REPO_PAYLOAD["id"], "full_name": "acme/api"}],
    })
    assert set((await _counts()).values()) == {0}


async def test_suspended_app_only_hides_the_team(db: None, gh: FakeGitHub) -> None:
    await _scanned_team(gh)
    await handle_installation_event("installation", {
        "action": "suspend", "installation": {"id": 77, "account": {"login": "acme"}}})
    counts = await _counts()
    assert counts["Team"] == 1 and counts["PushEvent"] == 2
    async with session_scope() as s:
        assert (await s.exec(select(Team))).one().installation_suspended
