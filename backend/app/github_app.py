"""GitHub App integration: webhook signatures, App JWT, installation tokens, REST calls."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt

from app.ast_engine import decode_source, is_analyzable_path
from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

ANNOTATIONS_PER_REQUEST = 50  # GitHub Checks API limit
NULL_SHA = "0" * 40
API_VERSION = "2022-11-28"


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def verify_webhook_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Constant-time check of ``X-Hub-Signature-256``."""
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def create_app_jwt(app_id: str, private_key_pem: str, now: int | None = None) -> str:
    """RS256 JWT identifying the App (valid 9 minutes; iat backdated for clock drift)."""
    if not app_id or not private_key_pem:
        raise GitHubError("GITHUB_APP_ID / private key not configured")
    issued = int(now if now is not None else time.time()) - 60
    payload = {"iat": issued, "exp": issued + 9 * 60, "iss": str(app_id)}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


@dataclass(slots=True)
class ChangedFile:
    path: str
    status: str  # added | modified | removed | renamed | copied | changed | unchanged
    blob_sha: str | None
    patch: str | None
    additions: int
    deletions: int
    previous_path: str | None = None


@dataclass(slots=True)
class Comparison:
    files: list[ChangedFile]
    total_files: int
    truncated: bool  # GitHub caps compare at 300 files


class _TokenCache:
    def __init__(self) -> None:
        self._tokens: dict[int, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    def get(self, installation_id: int) -> str | None:
        hit = self._tokens.get(installation_id)
        if hit and hit[1] - time.time() > 300:
            return hit[0]
        return None

    def put(self, installation_id: int, token: str, expires_at: float) -> None:
        self._tokens[installation_id] = (token, expires_at)


_token_cache = _TokenCache()


class GitHubApp:
    """Async GitHub REST client acting as the App or as one of its installations."""

    def __init__(self, settings: Settings | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings or get_settings()
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> GitHubApp:
        self._client = httpx.AsyncClient(
            base_url=self.settings.github_api_url.rstrip("/"), timeout=30.0,
            transport=self._transport,
            headers={"Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": API_VERSION,
                     "User-Agent": f"{self.settings.github_app_slug}-scanner"},
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("use `async with GitHubApp() as gh:`")
        return self._client

    # ---- low level ----------------------------------------------------------------------
    async def _request(self, method: str, url: str, *, token: str,
                       **kwargs: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"}
        for attempt in range(3):
            resp = await self.client.request(method, url, headers=headers, **kwargs)
            retryable = resp.status_code >= 500 or (
                resp.status_code in (403, 429) and (
                    resp.headers.get("retry-after") or
                    resp.headers.get("x-ratelimit-remaining") == "0"))
            if retryable and attempt < 2:
                delay = float(resp.headers.get("retry-after", "0") or 0) or 2.0 * (attempt + 1)
                await asyncio.sleep(min(delay, 20.0))
                continue
            if resp.status_code >= 400:
                raise GitHubError(f"{method} {url} -> {resp.status_code}: {resp.text[:500]}",
                                  resp.status_code)
            return resp
        raise GitHubError(f"{method} {url} failed after retries")

    async def installation_token(self, installation_id: int) -> str:
        cached = _token_cache.get(installation_id)
        if cached:
            return cached
        async with _token_cache._lock:
            cached = _token_cache.get(installation_id)
            if cached:
                return cached
            app_jwt = create_app_jwt(self.settings.github_app_id,
                                     self.settings.github_private_key_pem)
            resp = await self._request("POST", f"/app/installations/{installation_id}/"
                                       "access_tokens", token=app_jwt)
            data = resp.json()
            expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            _token_cache.put(installation_id, data["token"], expires.timestamp())
            return data["token"]

    # ---- installation-scoped API ----------------------------------------------------
    async def list_installation_repos(self, token: str) -> list[dict[str, Any]]:
        repos: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._request("GET", "/installation/repositories", token=token,
                                       params={"per_page": 100, "page": page})
            batch = resp.json().get("repositories", [])
            repos.extend(batch)
            if len(batch) < 100:
                return repos
            page += 1

    async def create_check_run(self, token: str, owner: str, repo: str, head_sha: str, *,
                               name: str, details_url: str | None = None,
                               external_id: str | None = None) -> int:
        body: dict[str, Any] = {
            "name": name, "head_sha": head_sha, "status": "in_progress",
            "started_at": _iso_now(),
            "output": {"title": "Scanning push…",
                       "summary": "ZeroDay Score is building the cross-file call graph and "
                                  "running the AI vulnerability analysis."},
        }
        if details_url:
            body["details_url"] = details_url
        if external_id:
            body["external_id"] = external_id
        resp = await self._request("POST", f"/repos/{owner}/{repo}/check-runs", token=token,
                                   json=body)
        return int(resp.json()["id"])

    async def complete_check_run(self, token: str, owner: str, repo: str, check_run_id: int, *,
                                 conclusion: str, title: str, summary: str, text: str = "",
                                 annotations: list[dict[str, Any]] | None = None,
                                 details_url: str | None = None) -> None:
        """Finish a check run, sending annotations in batches of 50 (GitHub appends them)."""
        annotations = annotations or []
        batches = [annotations[i:i + ANNOTATIONS_PER_REQUEST]
                   for i in range(0, len(annotations), ANNOTATIONS_PER_REQUEST)] or [[]]
        output = {"title": title[:255], "summary": summary[:65_000], "text": text[:65_000]}
        url = f"/repos/{owner}/{repo}/check-runs/{check_run_id}"
        for batch in batches[:-1]:
            await self._request("PATCH", url, token=token,
                                json={"output": {**output, "annotations": batch}})
        final: dict[str, Any] = {
            "status": "completed", "conclusion": conclusion, "completed_at": _iso_now(),
            "output": {**output, "annotations": batches[-1]},
        }
        if details_url:
            final["details_url"] = details_url
        await self._request("PATCH", url, token=token, json=final)

    async def open_pull_request_with_files(
            self, token: str, owner: str, repo: str, *, base_branch: str, base_sha: str,
            branch: str, files: dict[str, str], commit_message: str, title: str, body: str,
    ) -> tuple[int, str]:
        """Commit ``files`` on top of ``base_sha`` in a new branch and open a pull request.

        Needs the App's Contents and Pull requests permissions set to write.
        """
        base = await self._request("GET", f"/repos/{owner}/{repo}/git/commits/{base_sha}",
                                   token=token)
        tree = await self._request("POST", f"/repos/{owner}/{repo}/git/trees", token=token, json={
            "base_tree": base.json()["tree"]["sha"],
            "tree": [{"path": path, "mode": "100644", "type": "blob", "content": content}
                     for path, content in sorted(files.items())],
        })
        commit = await self._request("POST", f"/repos/{owner}/{repo}/git/commits", token=token,
                                     json={"message": commit_message,
                                           "tree": tree.json()["sha"], "parents": [base_sha]})
        await self._request("POST", f"/repos/{owner}/{repo}/git/refs", token=token,
                            json={"ref": f"refs/heads/{branch}", "sha": commit.json()["sha"]})
        pr = await self._request("POST", f"/repos/{owner}/{repo}/pulls", token=token, json={
            "title": title, "head": branch, "base": base_branch, "body": body,
            "maintainer_can_modify": True})
        data = pr.json()
        return int(data["number"]), str(data["html_url"])

    async def compare(self, token: str, owner: str, repo: str, base: str, head: str
                      ) -> Comparison:
        files: list[ChangedFile] = []
        total = 0
        page = 1
        while True:
            resp = await self._request("GET", f"/repos/{owner}/{repo}/compare/{base}...{head}",
                                       token=token, params={"per_page": 100, "page": page})
            data = resp.json()
            batch = data.get("files", []) or []
            for f in batch:
                files.append(ChangedFile(
                    path=f["filename"], status=f.get("status", "modified"),
                    blob_sha=f.get("sha"), patch=f.get("patch"),
                    additions=int(f.get("additions", 0)), deletions=int(f.get("deletions", 0)),
                    previous_path=f.get("previous_filename"),
                ))
            total = max(total, len(files))
            if len(batch) < 100 or page >= 3:  # compare API returns at most 300 files
                return Comparison(files=files, total_files=total, truncated=len(files) >= 300)
            page += 1

    async def python_tree(self, token: str, owner: str, repo: str, ref: str, *,
                          max_files: int, max_bytes: int) -> list[tuple[str, str]]:
        """(path, blob_sha) of analyzable .py files at ``ref``."""
        resp = await self._request("GET", f"/repos/{owner}/{repo}/git/trees/{ref}",
                                   token=token, params={"recursive": "1"})
        data = resp.json()
        if data.get("truncated"):
            logger.warning("tree for %s/%s@%s is truncated; baseline is partial", owner, repo, ref)
        entries = [(e["path"], e["sha"]) for e in data.get("tree", [])
                   if e.get("type") == "blob" and is_analyzable_path(e["path"])
                   and int(e.get("size", 0)) <= max_bytes]
        return sorted(entries)[:max_files]

    async def blob_text(self, token: str, owner: str, repo: str, blob_sha: str) -> str:
        resp = await self._request("GET", f"/repos/{owner}/{repo}/git/blobs/{blob_sha}",
                                   token=token)
        data = resp.json()
        raw = base64.b64decode(data.get("content", "")) if data.get("encoding") == "base64" \
            else str(data.get("content", "")).encode()
        return decode_source(raw)

    async def fetch_blobs(self, token: str, owner: str, repo: str,
                          entries: list[tuple[str, str]], concurrency: int = 8
                          ) -> dict[str, str]:
        sem = asyncio.Semaphore(concurrency)

        async def one(path: str, sha: str) -> tuple[str, str | None]:
            async with sem:
                try:
                    return path, await self.blob_text(token, owner, repo, sha)
                except GitHubError as exc:
                    logger.warning("could not fetch %s: %s", path, exc)
                    return path, None

        results = await asyncio.gather(*(one(p, s) for p, s in entries))
        return {p: text for p, text in results if text is not None}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
