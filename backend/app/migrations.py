"""Startup migrations for databases created before teams became one-per-repository.

``create_all`` never alters an existing table, so the schema step adds ``teams.github_repo_id``
and drops the old one-team-per-installation unique index. The data step then splits every team
that still covers several repositories: each repository gets its own team (its pushes, score
history and Discord settings move with it) and developer scores are rebuilt from the stored
pushes, since each team keeps its own leaderboard.

Both steps are idempotent: a database that is already split is left untouched.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.ai_scanner import ScanFinding
from app.config import get_settings
from app.db import get_engine, session_scope
from app.models import (
    Developer,
    Finding,
    PushEvent,
    Repository,
    ScoreSnapshot,
    Team,
    TeamIntegration,
)
from app.scoring import CraftSubscores, apply_push

logger = logging.getLogger(__name__)

_AGGREGATES = ("total_pushes", "faulty_pushes", "weighted_fault_sum", "security_score",
               "craft_samples", "craft_docs_sum", "craft_readability_sum", "craft_types_sum",
               "craft_score", "composite_score", "clean_streak", "best_clean_streak",
               "cwe_counts", "smell_counts", "top_cwe", "top_smell", "last_push_at")
_PROFILE = ("github_id", "display_name", "email", "avatar_url", "role",
            "linked_dashboard_account")


async def migrate() -> None:
    await _migrate_schema(get_engine())
    async with session_scope() as session:
        await split_multi_repo_teams(session)


async def _migrate_schema(engine: AsyncEngine) -> None:
    def inspect_teams(conn) -> tuple[set[str], dict[str, bool]]:
        insp = inspect(conn)
        return ({c["name"] for c in insp.get_columns("teams")},
                {i["name"]: bool(i["unique"]) for i in insp.get_indexes("teams")})

    async with engine.begin() as conn:
        columns, indexes = await conn.run_sync(inspect_teams)
        if "github_repo_id" not in columns:
            await conn.execute(text("ALTER TABLE teams ADD COLUMN github_repo_id BIGINT"))
            await conn.execute(text(
                "CREATE UNIQUE INDEX ix_teams_github_repo_id ON teams (github_repo_id)"))
            logger.info("migration: added teams.github_repo_id")
        if indexes.get("ix_teams_github_installation_id"):
            await conn.execute(text("DROP INDEX ix_teams_github_installation_id"))
            await conn.execute(text("CREATE INDEX ix_teams_github_installation_id "
                                    "ON teams (github_installation_id)"))
            logger.info("migration: teams.github_installation_id is no longer unique")


async def split_multi_repo_teams(session: AsyncSession) -> None:
    from app.pipeline import unique_team_slug  # pipeline imports are heavy; keep this lazy

    legacy = (await session.exec(select(Team).where(
        col(Team.github_installation_id).is_not(None),
        col(Team.github_repo_id).is_(None)))).all()
    for team in legacy:
        repos = (await session.exec(select(Repository).where(
            Repository.team_id == team.id).order_by(col(Repository.id)))).all()
        if not repos:
            continue
        integration = (await session.exec(select(TeamIntegration).where(
            TeamIntegration.team_id == team.id))).first()
        first, *others = repos
        team.name, team.github_repo_id = first.name, first.github_repo_id
        session.add(team)
        teams = [team]
        for repo in others:
            new = Team(name=repo.name, github_repo_id=repo.github_repo_id,
                       slug=await unique_team_slug(session, repo.owner, repo.name,
                                                   repo.github_repo_id),
                       github_installation_id=team.github_installation_id,
                       github_account_login=team.github_account_login,
                       github_account_id=team.github_account_id,
                       github_account_type=team.github_account_type,
                       installation_suspended=team.installation_suspended)
            session.add(new)
            await session.flush()
            repo.team_id = new.id
            session.add(repo)
            for push in (await session.exec(select(PushEvent).where(
                    PushEvent.repository_id == repo.id))).all():
                push.team_id = new.id
                session.add(push)
            if integration is not None:
                session.add(TeamIntegration(
                    team_id=new.id, discord_webhook_url=integration.discord_webhook_url,
                    discord_include_warnings=integration.discord_include_warnings))
            teams.append(new)
        await session.flush()
        if others:
            await _rebuild_scores(session, team, teams)
        logger.info("migration: team %s split into %s", team.slug, [t.slug for t in teams])


async def _rebuild_scores(session: AsyncSession, source: Team, teams: list[Team]) -> None:
    """Replay every scored push, in order, onto per-team developer rows."""
    threshold = get_settings().readability_neutral_threshold
    originals = {d.id: d for d in (await session.exec(select(Developer).where(
        Developer.team_id == source.id))).all()}
    fresh = Developer()
    for dev in originals.values():
        for field in _AGGREGATES:
            setattr(dev, field, getattr(fresh, field))
        session.add(dev)
    devs: dict[tuple[int, str], Developer] = {
        (source.id, d.github_login): d for d in originals.values()}  # type: ignore[misc]
    used: set[tuple[int, str]] = set()

    team_ids = [t.id for t in teams]
    rows = (await session.exec(
        select(PushEvent, ScoreSnapshot)
        .join(ScoreSnapshot, col(ScoreSnapshot.push_event_id) == col(PushEvent.id))
        .where(col(PushEvent.team_id).in_(team_ids))
        .order_by(col(PushEvent.completed_at), col(PushEvent.id)))).all()
    for push, snap in rows:
        original = originals.get(push.developer_id)
        login = original.github_login if original else push.author_login
        key = (push.team_id, login)
        dev = devs.get(key)
        if dev is None:
            dev = Developer(team_id=push.team_id, github_login=login,
                            **{f: getattr(original, f) for f in _PROFILE if original})
            session.add(dev)
            await session.flush()
            devs[key] = dev
        used.add(key)
        findings = [_scan_finding(f) for f in (await session.exec(select(Finding).where(
            Finding.push_event_id == push.id))).all()]
        craft = (CraftSubscores(push.docs_score, push.readability_score, push.type_hints_score)
                 if push.craft_push_score is not None and push.docs_score is not None
                 and push.readability_score is not None and push.type_hints_score is not None
                 else None)
        score = apply_push(dev, findings, craft, readability_threshold=threshold,
                           now=push.completed_at or push.created_at)
        push.developer_id = dev.id
        push.security_before, push.security_after = score.security_before, score.security_after
        push.craft_before, push.craft_after = score.craft_before, score.craft_after
        push.composite_before, push.composite_after = (score.composite_before,
                                                       score.composite_after)
        push.points_delta = score.points_delta
        snap.team_id, snap.developer_id = dev.team_id, dev.id
        snap.security_score, snap.craft_score = dev.security_score, dev.craft_score
        snap.composite_score, snap.total_pushes = dev.composite_score, dev.total_pushes
        snap.faulty_pushes, snap.points_delta = dev.faulty_pushes, score.points_delta
        session.add_all([dev, push, snap])

    # Unscored pushes (no Python changes) still need a developer on the right team.
    for push in (await session.exec(select(PushEvent).where(
            col(PushEvent.team_id).in_(team_ids)))).all():
        original = originals.get(push.developer_id)
        if original is None or original.team_id == push.team_id:
            continue
        key = (push.team_id, original.github_login)
        dev = devs.get(key)
        if dev is None:
            dev = Developer(team_id=push.team_id, github_login=original.github_login,
                            **{f: getattr(original, f) for f in _PROFILE})
            session.add(dev)
            await session.flush()
            devs[key] = dev
        used.add(key)
        push.developer_id = dev.id
        session.add(push)

    # Developers whose every push moved to another repository's team leave this one.
    for dev in originals.values():
        if (source.id, dev.github_login) not in used:
            await session.delete(dev)
    await session.flush()


def _scan_finding(f: Finding) -> ScanFinding:
    return ScanFinding(category=f.category, source=f.source, status=f.status,
                       severity=f.severity, rule_id=f.rule_id, title=f.title,
                       description=f.description, file_path=f.file_path,
                       start_line=f.start_line, end_line=f.end_line, cwe=f.cwe)
