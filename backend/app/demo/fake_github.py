"""In-memory GitHub REST API (one repository) served through ``httpx.MockTransport``.

Implements exactly the endpoints the pipeline uses: installation tokens, check runs,
recursive trees, blobs and commit comparison (with real unified-diff patches). Used by the
test-suite and by ``seed_demo.py`` so demo data is produced by the real scanning pipeline.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

FAKE_INSTALLATION_TOKEN = "ghs_fake"


def blob_sha(content: str) -> str:
    return hashlib.sha1(content.encode()).hexdigest()


class FakeGitHub:
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

    def compare_files(self, base: str, head: str) -> list[dict[str, Any]]:
        a, b = self.commits[base], self.commits[head]
        files = []
        for path in sorted(set(a) | set(b)):
            if a.get(path) == b.get(path):
                continue
            status = "added" if path not in a else ("removed" if path not in b else "modified")
            diff = list(difflib.unified_diff((a.get(path) or "").splitlines(),
                                             (b.get(path) or "").splitlines(), lineterm=""))
            body = [line for line in diff if not line.startswith(("---", "+++"))]
            files.append({
                "filename": path, "status": status,
                "sha": blob_sha(b[path]) if path in b else None, "patch": "\n".join(body),
                "additions": sum(1 for x in body if x.startswith("+")),
                "deletions": sum(1 for x in body if x.startswith("-")),
            })
        return files

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        prefix = f"/repos/{self.owner}/{self.repo}"
        if method == "POST" and re.fullmatch(r"/app/installations/\d+/access_tokens", path):
            if not request.headers.get("authorization", "").startswith("Bearer ey"):
                return httpx.Response(401, json={"message": "App JWT required"})
            exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            return httpx.Response(201, json={"token": FAKE_INSTALLATION_TOKEN, "expires_at": exp})
        if request.headers.get("authorization") != f"Bearer {FAKE_INSTALLATION_TOKEN}":
            return httpx.Response(401, json={"message": "Bad credentials"})
        if method == "POST" and path == f"{prefix}/check-runs":
            self._next_check += 1
            self.check_runs[self._next_check] = json.loads(request.content)
            return httpx.Response(201, json={"id": self._next_check})
        if method == "PATCH" and path.startswith(f"{prefix}/check-runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            body = json.loads(request.content)
            self.patches.append((run_id, body))
            run = self.check_runs[run_id]
            run.update({k: v for k, v in body.items() if k != "output"})
            run.setdefault("annotations", []).extend(
                body.get("output", {}).get("annotations", []))
            run["output"] = body.get("output")
            return httpx.Response(200, json={"id": run_id})
        if method == "GET" and path.startswith(f"{prefix}/git/trees/"):
            files = self.commits.get(path.rsplit("/", 1)[1])
            if files is None:
                return httpx.Response(404, json={"message": "Not Found"})
            tree = [{"path": p, "type": "blob", "sha": blob_sha(c), "size": len(c)}
                    for p, c in files.items()]
            return httpx.Response(200, json={"tree": tree, "truncated": False})
        if method == "GET" and path.startswith(f"{prefix}/git/blobs/"):
            content = self.blobs.get(path.rsplit("/", 1)[1])
            if content is None:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json={
                "encoding": "base64", "content": base64.b64encode(content.encode()).decode()})
        if method == "GET" and path.startswith(f"{prefix}/compare/"):
            base, head = path.rsplit("/", 1)[1].split("...")
            if base not in self.commits or head not in self.commits:
                return httpx.Response(404, json={"message": "Not Found"})
            if request.url.params.get("page", "1") != "1":
                return httpx.Response(200, json={"files": []})
            return httpx.Response(200, json={"files": self.compare_files(base, head)})
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
