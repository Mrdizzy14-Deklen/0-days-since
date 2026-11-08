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


def seed_commits(fake_github: FakeGitHub) -> FakeGitHub:
    """The commits every pipeline scenario uses: baseline A, vulnerable B, fixed C."""
    fake_github.commit("main", FILES_A)
    fake_github.commit(SHA_A, FILES_A)
    fake_github.commit(SHA_B, FILES_B)
    fake_github.commit(SHA_C, FILES_C)
    return fake_github


@pytest.fixture()
def gh(fake_github: FakeGitHub) -> FakeGitHub:
    return seed_commits(fake_github)


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
        board = (await client.get("/api/teams/api/leaderboard")).json()
        alice = board["developers"][0]
        assert alice["github_login"] == "alice" and alice["rank"] == 1
        assert alice["security_score"] == 455 and alice["fault_ratio"] == 0.5
        assert alice["top_cwe"] == "CWE-89"

        feed = (await client.get("/api/teams/api/pushes")).json()
        assert [p["id"] for p in feed] == [fix_id, push_id]
        assert feed[1]["conclusion"] == "failure" and feed[1]["vulns"]["high"] == 1

        detail = (await client.get(f"/api/pushes/{push_id}")).json()
        assert detail["vulnerabilities"][0]["cwe"] == "CWE-89"
        assert detail["team"]["slug"] == "api"
        scope = {m["file_path"]: m for m in detail["incident_scope"]}
        assert scope["app/db.py"]["compromised"] and "sql" in scope["app/db.py"]["sinks"]
        assert "app/routes/users.py" in scope
        path = detail["blast_radius"]["taint_paths"][0]
        assert path["nodes"][0] == "app.routes.users:get_user" and path["args_flow"]

        stats = (await client.get("/api/teams/api/stats")).json()
        assert stats["total_pushes"] == 2 and stats["faulty_pushes"] == 1
        assert stats["blocked_merges"] == 1 and stats["top_cwes"][0]["cwe"] == "CWE-89"

        trends = (await client.get("/api/teams/api/trends")).json()
        daily = (await client.get("/api/teams/api/daily")).json()
        assert daily["source"] == "computed"  # SQLite: no continuous aggregate
        assert sum(d["pushes"] for d in daily["series"]) == 2
        assert sum(d["faulty_pushes"] for d in daily["series"]) == 1
        assert [p["security"] for p in trends["series"]["alice"]] == [210, 455]

        dev_detail = (await client.get(f"/api/developers/{alice['id']}")).json()
        assert dev_detail["team"]["slug"] == "api"
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
        url = "/api/teams/api/leaderboard"
        assert (await client.get(url)).status_code == 401
        auth = {"Authorization": "Bearer s2s-token"}
        assert (await client.get(url, headers={**auth, "X-GitHub-Login": "mallory"})
                ).status_code == 404
        assert (await client.get(url, headers={**auth, "X-GitHub-Login": "alice"})
                ).status_code == 200
        # a teammate who never pushed sees the team through the GitHub App installation
        inst = {**auth, "X-GitHub-Login": "bob", "X-GitHub-Installations": "5,77"}
        assert (await client.get(url, headers=inst)).status_code == 200
        assert [t["slug"] for t in (await client.get("/api/teams", headers=inst)).json()] == \
            ["api"]
        # installations only count for a signed-in login
        anon_inst = {**auth, "X-GitHub-Installations": "77"}
        assert (await client.get(url, headers=anon_inst)).status_code == 404

        # PUBLIC_TEAMS: read-only for anyone, including signed-out visitors
        monkeypatch.setenv("PUBLIC_TEAMS", "api")
        get_settings.cache_clear()
        assert (await client.get(url, headers=auth)).status_code == 200
        teams = (await client.get("/api/teams", headers=auth)).json()
        assert teams[0]["slug"] == "api" and teams[0]["public"] is True


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


async def test_agent_opens_verified_fix_pr(db: None, gh: FakeGitHub,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings
    from app.fixer import FIX_SYSTEM
    from app.llm import LLMEndpoint

    monkeypatch.setenv("AGENT_OPEN_FIX_PRS", "true")
    get_settings.cache_clear()
    src = FILES_B["app/db.py"].split("\n")
    q = next(i for i, line in enumerate(src, start=1) if 'query = f"SELECT' in line)

    def handler(request: httpx.Request) -> httpx.Response:
        messages = json.loads(request.content)["messages"]
        system = messages[0]["content"]
        if "adversarial skeptic" in system:
            ids = [c["id"] for c in json.loads(
                messages[1]["content"].split("## Candidates to verify\n", 1)[1]
                .split("\n\n## Cross-file", 1)[0])]
            reply: dict[str, Any] = {"verdicts": [
                {"id": i, "verdict": "confirmed", "confidence": 0.9, "reasoning": "unsanitized"}
                for i in ids]}
        elif system == FIX_SYSTEM:
            reply = {"explanation": "Bind the id.", "commit_message": "Bind user id in fetch_user",
                     "edits": [{"file_path": "app/db.py", "start_line": q, "end_line": q + 2,
                                "replacement": "        cur = self.conn.cursor()\n"
                                "        cur.execute(\"SELECT * FROM users WHERE id = ?\", "
                                "(user_id,))"}]}
        else:  # agent: report straight away
            reply = {"action": "finish", "args": {"report": {
                "summary": "Formatted SQL in fetch_user.", "vulnerabilities": []}}}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(reply)}}]})

    scanner = AIScanner(LLMClient([LLMEndpoint("https://llm.test/v1", "k", "nemotron")],
                                  transport=httpx.MockTransport(handler)))
    await handle_installation_event("installation", {
        "action": "created",
        "installation": {"id": 77, "account": {"login": "acme", "id": 1, "type": "Organization"}},
        "repositories": [{"id": 555, "name": "api", "full_name": "acme/api"}],
    }, transport=gh.transport)
    job = job_from_push(push_payload(SHA_A, SHA_B, "Add user lookup"), "d-fix")
    assert job is not None
    push_id = await run_scan(job, gh_transport=gh.transport, scanner=scanner)

    assert len(gh.pulls) == 1
    pr = gh.pulls[0]
    assert pr["base"] == "main" and pr["head"] == f"zeroday/fix-{SHA_B[:7]}-1"
    fixed_sha = gh.refs[f"refs/heads/{pr['head']}"]
    assert 'WHERE id = ?", (user_id,))' in gh.commits[fixed_sha]["app/db.py"]
    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        assert push is not None and push.conclusion is CheckConclusion.FAILURE
        fix = push.agent_trace["fixes"][0]
        assert fix["verified"] and fix["pr_url"].endswith("/pull/1")
        assert push.agent_trace["investigation"]["finished"]
        assert {"agent_ms", "fixes_ms", "analysis_ms"} <= set(push.agent_trace["timings"])
    text = next(iter(gh.check_runs.values()))["output"]["text"]
    assert "Agent fixes" in text and "PR #1" in text
    get_settings.cache_clear()


async def test_bot_pushes_and_fix_branches_are_listed_not_scanned(db: None,
                                                                   gh: FakeGitHub) -> None:
    def payload(**over: Any) -> dict[str, Any]:
        p = push_payload(SHA_A, SHA_B, "x")
        p.update(over)
        return p

    human = job_from_push(payload(), "d")
    assert human is not None and human.skip_reason is None
    app_bot = {"login": "0-days-since[bot]", "id": 9, "type": "Bot"}
    head = {**push_payload(SHA_A, SHA_B, "x")["head_commit"],
            "author": {"username": "dependabot[bot]", "name": "dependabot"}}
    bots = [job_from_push(payload(sender=app_bot), "d"),
            job_from_push(payload(head_commit=head), "d"),
            job_from_push(payload(ref="refs/heads/zeroday/fix-abc1234-1"), "d")]
    assert all(j is not None and j.skip_reason for j in bots)

    push_id = await run_scan(job_from_push(payload(sender=app_bot), "d-bot"),
                             gh_transport=gh.transport, scanner=_deterministic())
    assert push_id is not None and not gh.check_runs
    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        assert push.status is ScanStatus.COMPLETED and push.conclusion is None
        assert push.developer_id is None
        assert not (await s.exec(select(Developer))).all()


async def test_scans_cut_off_by_a_restart_are_resumed(db: None, gh: FakeGitHub) -> None:
    from app.pipeline import resume_interrupted_scans

    # a real scan creates team/repo/developer; then simulate a push whose scan was killed
    await run_scan(job_from_push(push_payload(SHA_A, SHA_A, "seed"), "d-0"),
                   gh_transport=gh.transport, scanner=_deterministic())
    async with session_scope() as s:
        seed = (await s.exec(select(PushEvent))).one()
        stuck = PushEvent(team_id=seed.team_id, repository_id=seed.repository_id,
                          developer_id=seed.developer_id, delivery_id="d-1",
                          event_type=seed.event_type, ref="refs/heads/main", before_sha=SHA_A,
                          after_sha=SHA_B, commit_message="Add user lookup",
                          author_login="alice", status=ScanStatus.IN_PROGRESS)
        bot = PushEvent(team_id=seed.team_id, repository_id=seed.repository_id,
                        delivery_id="d-bot", event_type=seed.event_type,
                        ref="refs/heads/zeroday/fix-abc1234-1", after_sha=SHA_C,
                        author_login="0-days-since[bot]", status=ScanStatus.IN_PROGRESS)
        s.add_all([stuck, bot])
        await s.flush()
        stuck_id, bot_id = stuck.id, bot.id

    assert await resume_interrupted_scans(gh_transport=gh.transport,
                                          scanner=_deterministic()) == [stuck_id]
    async with session_scope() as s:
        push = await s.get(PushEvent, stuck_id)
        assert push.status is ScanStatus.COMPLETED and push.conclusion is CheckConclusion.FAILURE
        assert push.check_run_id is not None and push.quality_metrics
        bot_push = await s.get(PushEvent, bot_id)
        assert bot_push.status is ScanStatus.COMPLETED and bot_push.conclusion is None
    run = gh.check_runs[max(gh.check_runs)]
    assert run["head_sha"] == SHA_B and run["status"] == "completed"
    # nothing left to resume
    assert await resume_interrupted_scans(gh_transport=gh.transport,
                                          scanner=_deterministic()) == []
