"""Discord channel notifications: URL validation, message content, pipeline hook, API."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app import discord
from app.db import session_scope
from app.models import Team, TeamIntegration
from app.pipeline import job_from_push, run_scan
from tests.conftest import FakeGitHub
from tests.test_pipeline import (
    FILES_C,
    SHA_A,
    SHA_B,
    SHA_C,
    _deterministic,
    push_payload,
    seed_commits,
)

HOOK = "https://discord.com/api/webhooks/123456789012345678/" + "T0ken_-" * 6


class FakeDiscord:
    def __init__(self, status: int = 204) -> None:
        self.status = status
        self.sent: list[dict[str, Any]] = []
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(HOOK)
        self.sent.append(json.loads(request.content))
        return httpx.Response(self.status)


@pytest.fixture()
def gh(fake_github: FakeGitHub) -> FakeGitHub:
    return seed_commits(fake_github)


@pytest.fixture()
def fake_discord(monkeypatch: pytest.MonkeyPatch) -> FakeDiscord:
    fake = FakeDiscord()
    monkeypatch.setattr(discord, "transport", fake.transport)
    return fake


def test_only_discord_webhook_urls_are_accepted() -> None:
    assert discord.normalize_webhook_url(" " + HOOK + "?wait=true ") == HOOK
    assert discord.normalize_webhook_url(HOOK.replace("discord.com", "canary.discordapp.com")) \
        == HOOK
    for bad in ["http://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuv",
                "https://evil.example/api/webhooks/123456789012345678/abcdefghijklmnopqrstuv",
                "https://discord.com.evil.example/api/webhooks/1234567/abcdefghijklmnopqrstuv",
                "https://discord.com/api/webhooks/123/x", "https://169.254.169.254/latest"]:
        with pytest.raises(ValueError):
            discord.normalize_webhook_url(bad)
    masked = discord.mask_webhook_url(HOOK)
    assert masked and "T0ken" not in masked and "123456789012345678" in masked


async def _connect(include_warnings: bool = False) -> None:
    async with session_scope() as s:
        team = (await s.exec(Team.__table__.select())).first()  # type: ignore[attr-defined]
        s.add(TeamIntegration(team_id=team.id, discord_webhook_url=HOOK,
                              discord_include_warnings=include_warnings))


async def test_faulty_push_is_posted_and_fix_is_not(db: None, gh: FakeGitHub,
                                                    fake_discord: FakeDiscord) -> None:
    # first push creates the team; connect the channel, then ship a vulnerability
    seed = job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0")
    await run_scan(seed, gh_transport=gh.transport, scanner=_deterministic())
    await _connect()
    bad = job_from_push(push_payload(SHA_A, SHA_B, "Add user lookup\n\nbody"), "d-1")
    push_id = await run_scan(bad, gh_transport=gh.transport, scanner=_deterministic())

    assert len(fake_discord.sent) == 1
    msg = fake_discord.sent[0]
    assert msg["allowed_mentions"] == {"parse": []}  # commit text can never ping anyone
    embed = msg["embeds"][0]
    assert embed["title"] == "🚨 Merge blocked · acme/api"
    assert embed["url"] == f"http://dash.test/pushes/{push_id}"
    assert "**Add user lookup**" in embed["description"] and "@alice" in embed["description"]
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["Days since last incident"].startswith("**0** (first incident")
    assert "app/db.py:" in fields["What to fix"] and fields["Score"].startswith("▼")

    # the fix push is clean: nothing posted (warnings are off by default)
    good = job_from_push(push_payload(SHA_B, SHA_C, "Parameterize query"), "d-2")
    gh.commit(SHA_C, FILES_C)
    await run_scan(good, gh_transport=gh.transport, scanner=_deterministic())
    assert len(fake_discord.sent) == 1
    async with session_scope() as s:
        row = (await s.exec(TeamIntegration.__table__.select())).first()  # type: ignore[attr-defined]
        assert row.discord_last_sent_at is not None and row.discord_last_error is None


async def test_broken_webhook_never_fails_the_scan(db: None, gh: FakeGitHub,
                                                   fake_discord: FakeDiscord) -> None:
    fake_discord.status = 404
    await run_scan(job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0"),
                   gh_transport=gh.transport, scanner=_deterministic())
    await _connect()
    push_id = await run_scan(job_from_push(push_payload(SHA_A, SHA_B, "x"), "d-1"),
                             gh_transport=gh.transport, scanner=_deterministic())
    assert push_id is not None and gh.check_runs[max(gh.check_runs)]["conclusion"] == "failure"
    async with session_scope() as s:
        row = (await s.exec(TeamIntegration.__table__.select())).first()  # type: ignore[attr-defined]
        assert "Copy a fresh webhook URL" in row.discord_last_error


async def test_integration_api(db: None, gh: FakeGitHub, fake_discord: FakeDiscord,
                               monkeypatch: pytest.MonkeyPatch) -> None:
    await run_scan(job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0"),
                   gh_transport=gh.transport, scanner=_deterministic())
    from app.config import get_settings
    from app.main import app

    monkeypatch.setenv("API_TOKEN", "s2s")
    monkeypatch.setenv("PUBLIC_TEAMS", "api")
    get_settings.cache_clear()
    auth = {"Authorization": "Bearer s2s"}
    alice = {**auth, "X-GitHub-Login": "alice"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://api.test") as client:
        base = "/api/teams/api/integrations"
        state = (await client.get(base, headers=alice)).json()
        assert state["can_edit"] and not state["discord"]["connected"]
        # public read-only visitors may look but not change anything
        assert (await client.get(base, headers=auth)).json()["can_edit"] is False
        assert (await client.put(f"{base}/discord", headers=auth,
                                 json={"webhook_url": HOOK})).status_code == 403
        # not a Discord URL: rejected before any request is made
        bad = await client.put(f"{base}/discord", headers=alice,
                               json={"webhook_url": "https://example.com/hook"})
        assert bad.status_code == 422 and not fake_discord.sent

        ok = await client.put(f"{base}/discord", headers=alice,
                              json={"webhook_url": HOOK, "include_warnings": True})
        assert ok.status_code == 200
        body = ok.json()["discord"]
        assert body["connected"] and body["include_warnings"] and "T0ken" not in json.dumps(body)
        assert fake_discord.sent[-1]["embeds"][0]["title"] == "✅ Channel connected"

        assert (await client.post(f"{base}/discord/test", headers=alice)).status_code == 200
        assert len(fake_discord.sent) == 2
        # toggle without re-sending the URL keeps the channel
        kept = await client.put(f"{base}/discord", headers=alice, json={"include_warnings": False})
        assert kept.json()["discord"]["connected"]
        gone = await client.delete(f"{base}/discord", headers=alice)
        assert gone.json()["discord"]["connected"] is False
