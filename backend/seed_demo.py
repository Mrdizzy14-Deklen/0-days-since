"""Seed a demo team by replaying three weeks of pushes through the real scanning pipeline.

    python seed_demo.py            # create the "acme-fintech" demo team (offline replay)
    python seed_demo.py --reset    # delete and recreate it
    python seed_demo.py --live-llm # analyze the scripted commits with the configured LLM

GitHub is simulated in-process (no network, no real App needed). The AST graph, static
rules, blast radius, scoring and Check Run output are all produced by the production code.
In the default replay mode the two AI passes are answered from the scenario script
(model label ``demo-replay``); with ``--live-llm`` your configured Nemotron/fallback model
analyzes the same commits and the scripted expectations are reported, not enforced.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, update
from sqlmodel import col, select

from app.ai_scanner import AIScanner
from app.config import get_settings
from app.db import dispose_db, init_db, session_scope
from app.demo.fake_github import FakeGitHub
from app.demo.replay_llm import ReplayLLM
from app.demo.scenario import (
    BASE_FILES,
    DEVELOPERS,
    INSTALLATION_ID,
    REPO_ID,
    REPO_NAME,
    REPO_OWNER,
    STEPS,
    build_trees,
)
from app.llm import LLMClient
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
)
from app.pipeline import graph_cache, handle_installation_event, job_from_push, run_scan

REPO_PAYLOAD = {
    "id": REPO_ID, "name": REPO_NAME, "full_name": f"{REPO_OWNER}/{REPO_NAME}",
    "private": True, "default_branch": "main",
    "owner": {"login": REPO_OWNER, "id": 920_001, "type": "Organization"},
}


@dataclass(slots=True)
class SeedRow:
    when: datetime
    author: str
    message: str
    expected: str
    conclusion: str
    delta: int
    composite: int | None


@dataclass(slots=True)
class SeedReport:
    team_slug: str
    rows: list[SeedRow] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)


def _sha(i: int) -> str:
    return hashlib.sha1(f"zeroday-demo-commit-{i}".encode()).hexdigest()


async def purge_demo_team() -> bool:
    async with session_scope() as s:
        team = (await s.exec(select(Team).where(
            Team.github_installation_id == INSTALLATION_ID))).first()
        if team is None:
            return False
        repo_ids = list((await s.exec(select(Repository.id).where(
            Repository.team_id == team.id))).all())
        push_ids = list((await s.exec(select(PushEvent.id).where(
            PushEvent.team_id == team.id))).all())
        conn = await s.connection()
        if push_ids:
            await conn.execute(delete(Finding).where(col(Finding.push_event_id).in_(push_ids)))
        await conn.execute(delete(ScoreSnapshot).where(col(ScoreSnapshot.team_id) == team.id))
        await conn.execute(delete(PushEvent).where(col(PushEvent.team_id) == team.id))
        if repo_ids:
            for model in (CodeEdge, CodeSymbol, RepoFile):
                await conn.execute(delete(model).where(col(model.repository_id).in_(repo_ids)))
            for rid in repo_ids:
                graph_cache.drop(rid)
        await conn.execute(delete(Repository).where(col(Repository.team_id) == team.id))
        await conn.execute(delete(Developer).where(col(Developer.team_id) == team.id))
        await conn.execute(delete(Team).where(col(Team.id) == team.id))
    return True


def _push_payload(step_index: int, author: str, message: str) -> dict:
    dev = DEVELOPERS[author]
    after = _sha(step_index)
    return {
        "ref": "refs/heads/main", "before": _sha(step_index - 1), "after": after,
        "deleted": False, "installation": {"id": INSTALLATION_ID}, "repository": REPO_PAYLOAD,
        "sender": {"login": dev.login, "id": dev.github_id, "avatar_url": dev.avatar_url},
        "head_commit": {
            "id": after, "message": message,
            "url": f"https://github.com/{REPO_OWNER}/{REPO_NAME}/commit/{after}",
            "author": {"username": dev.login, "name": dev.name, "email": dev.email},
        },
    }


async def _backdate(push_id: int, when: datetime) -> None:
    """Move a scanned push (and its snapshot/findings) to its scripted point in time."""
    done = when + timedelta(seconds=37)
    async with session_scope() as s:
        push = await s.get(PushEvent, push_id)
        assert push is not None
        push.created_at, push.started_at, push.completed_at = when, when, done
        s.add(push)
        conn = await s.connection()
        await conn.execute(update(Finding).where(col(Finding.push_event_id) == push_id)
                           .values(created_at=done))
        # recorded_at is the hypertable partition key: re-insert rather than update it
        snaps = (await s.exec(select(ScoreSnapshot).where(
            ScoreSnapshot.push_event_id == push_id))).all()
        for snap in snaps:
            data = snap.model_dump(exclude={"id", "recorded_at"})
            await s.delete(snap)
            await s.flush()
            s.add(ScoreSnapshot(**data, recorded_at=done))
        if push.developer_id:
            dev = await s.get(Developer, push.developer_id)
            if dev is not None:
                dev.last_push_at = done
                s.add(dev)


async def seed(*, reset: bool = False, live_llm: bool = False, days_ago: int = 21,
               verbose: bool = True) -> SeedReport:
    await init_db()
    if reset:
        await purge_demo_team()
    else:
        async with session_scope() as s:
            if (await s.exec(select(Team.id).where(
                    Team.github_installation_id == INSTALLATION_ID))).first():
                raise SystemExit("Demo team already exists; re-run with --reset to recreate it.")

    trees = build_trees()
    github = FakeGitHub(REPO_OWNER, REPO_NAME)
    github.commit("main", BASE_FILES)
    for i, tree in enumerate(trees):
        github.commit(_sha(i), tree)

    await handle_installation_event("installation", {
        "action": "created",
        "installation": {"id": INSTALLATION_ID, "account": REPO_PAYLOAD["owner"]},
        "repositories": [{"id": REPO_ID, "name": REPO_NAME,
                          "full_name": REPO_PAYLOAD["full_name"], "private": True}],
    }, transport=github.transport)
    async with session_scope() as s:  # keep the public demo URL (and PUBLIC_TEAMS) stable
        team = (await s.exec(select(Team).where(Team.github_repo_id == REPO_ID))).one()
        team.slug = REPO_OWNER
        s.add(team)

    replay = ReplayLLM()
    if live_llm:
        llm = LLMClient.from_settings()
        if not llm.available:
            raise SystemExit("--live-llm needs LLM_API_KEY (or LLM_FALLBACK_API_KEY) set.")
    else:
        llm = replay.client()
    scanner = AIScanner(llm, context_chars=get_settings().llm_context_chars)

    start = (datetime.now(timezone.utc) - timedelta(days=days_ago)).replace(
        hour=9, minute=0, second=0, microsecond=0)
    report = SeedReport(team_slug=REPO_OWNER)
    for i, step in enumerate(STEPS, start=1):
        replay.step, replay.files = step, trees[i]
        job = job_from_push(_push_payload(i, step.author, step.message), f"demo-delivery-{i}")
        assert job is not None
        push_id = await run_scan(job, gh_transport=github.transport, scanner=scanner)
        if push_id is None:
            raise RuntimeError(f"step {i} was not scanned")
        when = start + timedelta(days=step.day)
        await _backdate(push_id, when)
        async with session_scope() as s:
            push = await s.get(PushEvent, push_id)
            assert push is not None
        conclusion = push.conclusion.value if push.conclusion else push.status.value
        if conclusion != step.expect.value:
            report.mismatches.append(f"step {i} ({step.message}): expected {step.expect.value}, "
                                     f"got {conclusion}{' - ' + push.error if push.error else ''}")
        report.rows.append(SeedRow(when, step.author, step.message, step.expect.value,
                                   conclusion, push.points_delta, push.composite_after))
        if verbose:
            mark = "✓" if conclusion == step.expect.value else "✗"
            print(f"  {mark} {when:%b %d %H:%M}  {step.author:<16} {conclusion:<8} "
                  f"{push.points_delta:+5d}  {step.message[:58]}")
    return report


async def _leaderboard() -> list[Developer]:
    async with session_scope() as s:
        team = (await s.exec(select(Team).where(
            Team.github_installation_id == INSTALLATION_ID))).one()
        return list((await s.exec(select(Developer).where(Developer.team_id == team.id)
                                  .order_by(col(Developer.composite_score).desc()))).all())


def _configure_offline_github() -> None:
    """Throwaway App credentials: only ever presented to the in-process fake GitHub."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    os.environ["GITHUB_APP_ID"] = "demo-seed"
    os.environ["GITHUB_APP_PRIVATE_KEY"] = pem.replace("\n", "\\n")
    os.environ["GITHUB_APP_PRIVATE_KEY_PATH"] = ""
    os.environ["GITHUB_API_URL"] = "https://github.demo.invalid"
    get_settings.cache_clear()


async def _main(args: argparse.Namespace) -> int:
    _configure_offline_github()
    mode = "live LLM" if args.live_llm else "offline replay"
    print(f"Seeding demo team '{REPO_OWNER}' ({len(STEPS)} pushes, {mode})…")
    try:
        report = await seed(reset=args.reset, live_llm=args.live_llm, days_ago=args.days)
        print("\nLeaderboard")
        for rank, d in enumerate(await _leaderboard(), start=1):
            print(f"  {rank}. {d.github_login:<16} {d.composite_score:>4}  "
                  f"(security {d.security_score:>3}, craft {d.craft_score:>3})  "
                  f"pushes {d.total_pushes:>2}, faulty {d.faulty_pushes}, "
                  f"streak {d.clean_streak}, top CWE {d.top_cwe or '-'}")
    finally:
        await dispose_db()
    if report.mismatches:
        print("\nScenario expectations not met:")
        for m in report.mismatches:
            print("  - " + m)
        return 0 if args.live_llm else 1
    print(f"\nDone. Open the dashboard team '{report.team_slug}'.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--reset", action="store_true", help="delete and recreate the demo team")
    parser.add_argument("--live-llm", action="store_true",
                        help="use the configured LLM instead of the scripted replay")
    parser.add_argument("--days", type=int, default=21, help="history length in days")
    sys.exit(asyncio.run(_main(parser.parse_args())))


if __name__ == "__main__":
    main()
