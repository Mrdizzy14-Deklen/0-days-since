"""The demo scenario replays through the real pipeline and meets every expectation."""

from __future__ import annotations

import ast

from sqlmodel import select

from app.db import session_scope
from app.demo.scenario import STEPS, build_trees
from app.enums import FindingStatus
from app.models import Developer, Finding, PushEvent, ScoreSnapshot
from seed_demo import purge_demo_team, seed


def test_scenario_trees_are_valid_python() -> None:
    trees = build_trees()
    assert len(trees) == len(STEPS) + 1
    for tree in trees:
        for path, source in tree.items():
            if path.endswith(".py"):
                ast.parse(source, filename=path)


async def test_seed_replays_scenario(db: None) -> None:
    report = await seed(verbose=False)
    assert report.mismatches == []
    assert len(report.rows) == len(STEPS)

    async with session_scope() as s:
        devs = {d.github_login: d for d in (await s.exec(select(Developer))).all()}
        pushes = (await s.exec(select(PushEvent))).all()
        findings = (await s.exec(select(Finding))).all()
        snapshots = (await s.exec(select(ScoreSnapshot))).all()

    assert len(devs) == 6 and all(d.total_pushes == 4 for d in devs.values())
    ranked = sorted(devs.values(), key=lambda d: -d.composite_score)
    assert {ranked[0].github_login, ranked[1].github_login} == {"maya-chen", "alex-kim"}
    assert devs["oscar-diaz"].top_cwe == "CWE-89"
    assert all(p.llm_model == "demo-replay" for p in pushes)
    # history is spread over the scenario window for the trend chart
    span = max(p.created_at for p in pushes) - min(p.created_at for p in pushes)
    assert span.days >= 19 and len(snapshots) == len(STEPS)

    rejected = [f for f in findings if f.status is FindingStatus.REJECTED]
    assert {f.rule_id for f in rejected} >= {"PY-SEC-009", "PY-SEC-100"}
    injection = next(f for f in findings if f.rule_id == "PY-SEC-001")
    assert injection.status is FindingStatus.VERIFIED
    assert "ignored" in (injection.verifier_reasoning or "")
    assert any(f.rule_id == "ZD-AI-001" for f in findings)
    assert any(f.rule_id == "AI-CWE-639" and f.counted_in_score for f in findings)

    sqli_push = next(p for p in pushes if p.commit_message == "Invoice search by customer email")
    paths = sqli_push.blast_radius["taint_paths"]
    assert paths and paths[0]["cross_file"] and "sql" in paths[0]["sink_kinds"]
    # the scripted agent investigated with real tool calls, then fixed and verified the SQLi
    investigation = sqli_push.agent_trace["investigation"]
    assert [st["action"] for st in investigation["steps"]] == [
        "symbol", "trace", "read_code", "finish"]
    assert "app/services/billing.py" in investigation["steps"][2]["observation"]
    fix = sqli_push.agent_trace["fixes"][0]
    assert fix["verified"] and "db.fetch_all(" in fix["diff"] and fix["pr_url"] is None

    assert await purge_demo_team()
    async with session_scope() as s:
        assert (await s.exec(select(PushEvent))).all() == []
