"""Shared fixtures: isolated SQLite DB per test, fake GitHub API, fake LLM endpoint."""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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


def blob_sha(content: str) -> str:
    return hashlib.sha1(content.encode()).hexdigest()


class FakeGitHub:
    """In-memory GitHub REST API for one repository (`acme/api`)."""

    def __init__(self, owner: str = "acme", repo: str = "api") -> None:
        self.owner, self.repo = owner, repo
        self.commits: dict[str, dict[str, str]] = {}
        self.blobs: dict[str, str] = {}
        self.check_runs: dict[int, dict[str, Any]] = {}
        self.patches: list[tuple[int, dict[str, Any]]] = []
        self._next_check = 1000

    def commit(self, sha: str, files: dict[str, str]) -> None:
        self.commits[sha] = dict(files)
        for content in files.values():
            self.blobs[blob_sha(content)] = content

    def _compare(self, base: str, head: str) -> dict[str, Any]:
        a, b = self.commits[base], self.commits[head]
        files = []
        for path in sorted(set(a) | set(b)):
            if a.get(path) == b.get(path):
                continue
            status = "added" if path not in a else ("removed" if path not in b else "modified")
            diff = list(difflib.unified_diff((a.get(path) or "").splitlines(),
                                             (b.get(path) or "").splitlines(), lineterm=""))
            patch = "\n".join(line for line in diff
                              if not line.startswith(("---", "+++")))
            files.append({
                "filename": path, "status": status,
                "sha": blob_sha(b[path]) if path in b else None, "patch": patch,
                "additions": sum(1 for x in diff if x.startswith("+") and
                                 not x.startswith("+++")),
                "deletions": sum(1 for x in diff if x.startswith("-") and
                                 not x.startswith("---")),
            })
        return {"files": files}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        prefix = f"/repos/{self.owner}/{self.repo}"
        if method == "POST" and re.fullmatch(r"/app/installations/\d+/access_tokens", path):
            assert request.headers["authorization"].startswith("Bearer ey")
            exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            return httpx.Response(201, json={"token": "ghs_fake", "expires_at": exp})
        assert request.headers.get("authorization") == "Bearer ghs_fake", path
        if method == "POST" and path == f"{prefix}/check-runs":
            self._next_check += 1
            self.check_runs[self._next_check] = json.loads(request.content)
            return httpx.Response(201, json={"id": self._next_check})
        if method == "PATCH" and path.startswith(f"{prefix}/check-runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            body = json.loads(request.content)
            self.patches.append((run_id, body))
            self.check_runs[run_id].update({k: v for k, v in body.items() if k != "output"})
            out = self.check_runs[run_id].setdefault("annotations", [])
            out.extend(body.get("output", {}).get("annotations", []))
            self.check_runs[run_id]["output"] = body.get("output")
            return httpx.Response(200, json={"id": run_id})
        if method == "GET" and path.startswith(f"{prefix}/git/trees/"):
            ref = path.rsplit("/", 1)[1]
            files = self.commits[ref]
            tree = [{"path": p, "type": "blob", "sha": blob_sha(c), "size": len(c)}
                    for p, c in files.items()]
            return httpx.Response(200, json={"tree": tree, "truncated": False})
        if method == "GET" and path.startswith(f"{prefix}/git/blobs/"):
            content = self.blobs[path.rsplit("/", 1)[1]]
            return httpx.Response(200, json={
                "encoding": "base64", "content": base64.b64encode(content.encode()).decode()})
        if method == "GET" and path.startswith(f"{prefix}/compare/"):
            base, head = path.rsplit("/", 1)[1].split("...")
            if request.url.params.get("page", "1") != "1":
                return httpx.Response(200, json={"files": []})
            return httpx.Response(200, json=self._compare(base, head))
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


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
