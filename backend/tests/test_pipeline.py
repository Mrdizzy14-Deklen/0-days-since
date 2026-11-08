"""End-to-end: install -> baseline -> vulnerable push -> fix push -> dashboard API."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx
import pytest
from sqlmodel import select

from app.ai_scanner import AIScanner
from app.db import session_scope
from app.enums import CheckConclusion, ScanStatus
from app.llm import LLMClient
from app.models import CodeSymbol, Developer, Finding, PushEvent, RepoFile, ScoreSnapshot
from app.pipeline import handle_installation_event, job_from_pull_request, job_from_push, run_scan
from tests.conftest import WEBHOOK_SECRET, FakeGitHub
from tests.test_ast_engine import REPO

SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40

FILES_A = {p: c for p, c in REPO.items() if not p.startswith(".venv")}
FILES_A["app/db.py"] = FILES_A["app/db.py"].replace(
    'query = f"SELECT * FROM users WHERE id = \'{user_id}\'"\n        cur = self.conn.cursor()\n'
    "        cur.execute(query)",
    'cur = self.conn.cursor()\n        cur.execute("SELECT * FROM users WHERE id = ?", '
    "(user_id,))",
)
FILES_B = {p: c for p, c in REPO.items() if not p.startswith(".venv")}  # introduces SQLi
FILES_C = {**FILES_A, "app/db.py": FILES_A["app/db.py"].replace(
    "    def fetch_user(self, user_id):\n",
    '    def fetch_user(self, user_id: str) -> tuple:\n        """Fetch one user row."""\n')}

REPO_PAYLOAD = {"id": 555, "name": "api", "full_name": "acme/api", "private": True,
                "default_branch": "main",
                "owner": {"login": "acme", "id": 1, "type": "Organization"}}


def push_payload(before: str, after: str, message: str) -> dict[str, Any]:
    return {
        "ref": "refs/heads/main", "before": before, "after": after, "deleted": False,
        "installation": {"id": 77}, "repository": REPO_PAYLOAD,
        "sender": {"login": "alice", "id": 1001, "avatar_url": "https://avatars.test/alice"},
        "head_commit": {"id": after, "message": message, "url": f"https://gh.test/{after}",
                        "author": {"username": "alice", "name": "Alice A",
                                   "email": "alice@example.com"}},
    }


@pytest.fixture()
def gh(fake_github: FakeGitHub) -> FakeGitHub:
    fake_github.commit("main", FILES_A)
    fake_github.commit(SHA_A, FILES_A)
    fake_github.commit(SHA_B, FILES_B)
    fake_github.commit(SHA_C, FILES_C)
    return fake_github


def _deterministic() -> AIScanner:
    return AIScanner(LLMClient([]))


async def test_end_to_end(db: None, gh: FakeGitHub) -> None:
    # ---- installation builds the baseline graph ---------------------------------------
    repo_ids = await handle_installation_event("installation", {
        "action": "created",
        "installation": {"id": 77, "account": {"login": "acme", "id": 1,
                                               "type": "Organization"}},
        "repositories": [{"id": 555, "name": "api", "full_name": "acme/api"}],
    }, transport=gh.transport)
    assert len(repo_ids) == 1
    async with session_scope() as s:
        files = (await s.exec(select(RepoFile.path))).all()
        assert "app/db.py" in files and len(files) == len(FILES_A)
        assert (await s.exec(select(CodeSymbol).where(
            CodeSymbol.node_id == "app.routes.users:get_user"))).one().is_entry_point

    # ---- vulnerable push fails the check ------------------------------------------------
    job = job_from_push(push_payload(SHA_A, SHA_B, "Add user lookup"), "delivery-1")
    assert job is not None
    push_id = await run_scan(job, gh_transport=gh.transport, scanner=_deterministic())
    assert push_id is not None

    run = gh.check_runs[max(gh.check_runs)]
    assert run["head_sha"] == SHA_B and run["status"] == "completed"
    assert run["conclusion"] == "failure"
    assert run["details_url"] == f"http://dash.test/pushes/{push_id}"
    failures = [a for a in run["annotations"] if a["annotation_level"] == "failure"]
    assert any(a["path"] == "app/db.py" and "CWE-89" in a["title"] for a in failures)
    assert run["output"]["title"].startswith("❌ 1 blocking vulnerability (−")

    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        dev = (await s.exec(select(Developer).where(Developer.github_login == "alice"))).one()
        assert push.status is ScanStatus.COMPLETED and push.conclusion is CheckConclusion.FAILURE
        assert push.vuln_high == 1 and push.is_faulty and push.files_changed == ["app/db.py"]
        assert dev.total_pushes == 1 and dev.faulty_pushes == 1
        assert dev.security_score == 210  # 700 * (1 - 0.7/1)
        assert push.points_delta == push.composite_after - push.composite_before < 0
        assert push.blast_radius["entry_points"] == ["app.routes.users:get_user"]
        assert dev.avatar_url == "https://avatars.test/alice" and dev.github_id == 1001
        findings = (await s.exec(select(Finding).where(Finding.push_event_id == push_id))).all()
        assert any(f.rule_id == "PY-SEC-003" and f.counted_in_score for f in findings)

    # ---- redelivery and same-SHA duplicates are ignored -----------------------------------
    assert await run_scan(job, gh_transport=gh.transport, scanner=_deterministic()) is None
    job_again = job_from_push(push_payload(SHA_A, SHA_B, "same commit"), "delivery-2")
    assert await run_scan(job_again, gh_transport=gh.transport, scanner=_deterministic()) is None

    # ---- the fix dilutes the fault rate ---------------------------------------------------
    fix = job_from_push(push_payload(SHA_B, SHA_C, "Parameterize user lookup"), "delivery-3")
    fix_id = await run_scan(fix, gh_transport=gh.transport, scanner=_deterministic())
    run = gh.check_runs[max(gh.check_runs)]
    assert run["conclusion"] in {"success", "neutral"}
    async with session_scope() as s:
        dev = (await s.exec(select(Developer).where(Developer.github_login == "alice"))).one()
        assert dev.total_pushes == 2 and dev.security_score == 455  # 700 * (1 - 0.7/2)
        fix_push = await s.get(PushEvent, fix_id)
        assert fix_push.points_delta > 0 and not fix_push.is_faulty
        assert len((await s.exec(select(ScoreSnapshot))).all()) == 2

    # ---- dashboard API -----------------------------------------------------------------
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://api.test") as client:
        board = (await client.get("/api/teams/acme/leaderboard")).json()
        alice = board["developers"][0]
        assert alice["github_login"] == "alice" and alice["rank"] == 1
        assert alice["security_score"] == 455 and alice["fault_ratio"] == 0.5
        assert alice["top_cwe"] == "CWE-89"

        feed = (await client.get("/api/teams/acme/pushes")).json()
        assert [p["id"] for p in feed] == [fix_id, push_id]
        assert feed[1]["conclusion"] == "failure" and feed[1]["vulns"]["high"] == 1

        detail = (await client.get(f"/api/pushes/{push_id}")).json()
        assert detail["vulnerabilities"][0]["cwe"] == "CWE-89"
        assert detail["team"]["slug"] == "acme"
        scope = {m["file_path"]: m for m in detail["incident_scope"]}
        assert scope["app/db.py"]["compromised"] and "sql" in scope["app/db.py"]["sinks"]
        assert "app/routes/users.py" in scope
        path = detail["blast_radius"]["taint_paths"][0]
        assert path["nodes"][0] == "app.routes.users:get_user" and path["args_flow"]

        stats = (await client.get("/api/teams/acme/stats")).json()
        assert stats["total_pushes"] == 2 and stats["faulty_pushes"] == 1
        assert stats["blocked_merges"] == 1 and stats["top_cwes"][0]["cwe"] == "CWE-89"

        trends = (await client.get("/api/teams/acme/trends")).json()
        assert [p["security"] for p in trends["series"]["alice"]] == [210, 455]

        dev_detail = (await client.get(f"/api/developers/{alice['id']}")).json()
        assert dev_detail["team"]["slug"] == "acme"
        assert len(dev_detail["history"]) == 2 and len(dev_detail["recent_pushes"]) == 2

        assert (await client.get("/api/teams/nope/leaderboard")).status_code == 404


async def test_api_token_enforces_team_membership(db: None, gh: FakeGitHub,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    job = job_from_push(push_payload(SHA_A, SHA_B, "x"), "d-1")
    await run_scan(job, gh_transport=gh.transport, scanner=_deterministic())
    from app.config import get_settings
    from app.main import app

    monkeypatch.setenv("API_TOKEN", "s2s-token")
    get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://api.test") as client:
        url = "/api/teams/acme/leaderboard"
        assert (await client.get(url)).status_code == 401
        auth = {"Authorization": "Bearer s2s-token"}
        assert (await client.get(url, headers={**auth, "X-GitHub-Login": "mallory"})
                ).status_code == 404
        assert (await client.get(url, headers={**auth, "X-GitHub-Login": "alice"})
                ).status_code == 200


async def test_scan_error_reports_neutral_check(db: None, gh: FakeGitHub) -> None:
    job = job_from_push(push_payload("f" * 40, SHA_B, "unknown base"), "d-err")
    # first scan without a stored graph fetches the baseline at SHA_B, then compare fails
    push_id = await run_scan(job, gh_transport=gh.transport, scanner=_deterministic())
    run = gh.check_runs[max(gh.check_runs)]
    assert run["conclusion"] == "neutral" and "could not complete" in run["output"]["title"]
    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        assert push.status is ScanStatus.FAILED and push.error


async def test_non_python_push_is_not_scored(db: None, gh: FakeGitHub) -> None:
    gh.commit("d" * 40, {**FILES_A, "README.md": "# docs"})
    await run_scan(job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0"),
                   gh_transport=gh.transport, scanner=_deterministic())
    job = job_from_push(push_payload(SHA_A, "d" * 40, "docs only"), "d-1")
    push_id = await run_scan(job, gh_transport=gh.transport, scanner=_deterministic())
    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        dev = (await s.exec(select(Developer))).one()
        assert push.conclusion is CheckConclusion.SUCCESS and dev.total_pushes == 0


def test_job_parsing_edge_cases() -> None:
    assert job_from_push({**push_payload(SHA_A, "0" * 40, "x"), "deleted": True}, "d") is None
    assert job_from_push({**push_payload(SHA_A, SHA_B, "x"), "ref": "refs/tags/v1"}, "d") is None
    new_branch = job_from_push(push_payload("0" * 40, SHA_B, "x"), "d")
    assert new_branch is not None and new_branch.before_sha is None
    pr = {"action": "synchronize", "installation": {"id": 77}, "repository": REPO_PAYLOAD,
          "pull_request": {"number": 9, "title": "t", "html_url": "u",
                           "user": {"login": "eve", "id": 5},
                           "head": {"sha": SHA_B, "repo": {"id": 999}},
                           "base": {"sha": SHA_A, "repo": {"id": 555}}}}
    fork_job = job_from_pull_request(pr, "d")
    assert fork_job is not None and fork_job.pr_number == 9 and fork_job.author_login == "eve"
    pr["pull_request"]["head"]["repo"]["id"] = 555  # same-repo PR: covered by push event
    assert job_from_pull_request(pr, "d") is None


async def test_webhook_endpoint(db: None, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.main as main_module

    queued: list[Any] = []

    async def fake_run_scan(job: Any) -> None:
        queued.append(job)

    monkeypatch.setattr(main_module, "run_scan", fake_run_scan)
    body = json.dumps(push_payload(SHA_A, SHA_B, "hello")).encode()
    sig = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main_module.app),
                                 base_url="http://api.test") as client:
        bad = await client.post("/api/webhooks/github", content=body,
                                headers={"X-GitHub-Event": "push",
                                         "X-Hub-Signature-256": "sha256=deadbeef"})
        assert bad.status_code == 401
        ok = await client.post("/api/webhooks/github", content=body,
                               headers={"X-GitHub-Event": "push", "X-GitHub-Delivery": "abc",
                                        "X-Hub-Signature-256": sig})
        assert ok.status_code == 202 and ok.json()["queued"] == "scan"
    assert len(queued) == 1 and queued[0].author_login == "alice"
    assert queued[0].delivery_id == "abc"
