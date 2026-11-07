"""Shared fixtures: isolated SQLite DB per test, fake GitHub API, fake LLM endpoint."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.demo.fake_github import FakeGitHub

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _KEY.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()
PUBLIC_PEM = _KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo
                                            ).decode()
WEBHOOK_SECRET = "test-webhook-secret"

# Must be set before app modules read settings.
os.environ.update({
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "GITHUB_WEBHOOK_SECRET": WEBHOOK_SECRET,
    "GITHUB_APP_ID": "123456",
    "GITHUB_APP_PRIVATE_KEY": PRIVATE_PEM.replace("\n", "\\n"),
    "GITHUB_API_URL": "https://api.github.test",
    "LLM_API_KEY": "",
    "LLM_FALLBACK_API_KEY": "",
    "API_TOKEN": "",
    "FRONTEND_ORIGIN": "http://dash.test",
    "ENABLE_TIMESCALE": "false",
})


@pytest.fixture()
async def db(tmp_path, monkeypatch) -> AsyncIterator[None]:
    from app import db as db_module
    from app.config import get_settings

    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    get_settings.cache_clear()
    await db_module.dispose_db()
    await db_module.init_db()
    from app.pipeline import graph_cache
    graph_cache._graphs.clear()
    yield
    await db_module.dispose_db()
    get_settings.cache_clear()


@pytest.fixture()
def fake_github() -> FakeGitHub:
    return FakeGitHub()


def llm_transport(responder: Callable[[str, str], dict[str, Any] | str],
                  calls: list[dict[str, Any]] | None = None) -> httpx.MockTransport:
    """Fake OpenAI-compatible endpoint; ``responder(system, user)`` returns the reply."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        system = body["messages"][0]["content"]
        user = body["messages"][1]["content"]
        if calls is not None:
            calls.append(body)
        reply = responder(system, user)
        content = reply if isinstance(reply, str) else json.dumps(reply)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return httpx.MockTransport(handler)
