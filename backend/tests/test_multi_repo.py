"""One installation, several repositories: scans and installs run concurrently."""

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
    """Serve every acme/svcN repository from the fake's single repository."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url.copy_with(path=re.sub(r"^/repos/acme/svc\d+", "/repos/acme/api",
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
        assert len((await s.exec(select(Team))).all()) == 1
        assert len((await s.exec(select(Repository))).all()) == len(repos)
        dev = (await s.exec(select(Developer))).one()
        pushes = (await s.exec(select(PushEvent))).all()
        assert len(pushes) == 2 * len(repos)
        assert dev.total_pushes == 2 * len(repos)
