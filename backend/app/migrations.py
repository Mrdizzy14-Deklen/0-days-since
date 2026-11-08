"""Startup migrations for databases created before teams became one-per-repository.

``create_all`` never alters an existing table, so the schema step adds ``teams.github_repo_id``
and drops the old one-team-per-installation unique index.

The data step then regroups every legacy team (one per installation, named after the account)
into one team per repository. A repository can appear under several legacy teams when the App
was reinstalled (each installation got its own team), so its rows are merged first: pushes and
findings move to the newest repository row, and that repository's team keeps all of them.
Teams are renamed after their repository, Discord settings carry over, emptied legacy teams
are removed, and developer scores are rebuilt by replaying the stored pushes, since each team
keeps its own leaderboard.

Both steps are idempotent: a database that is already split is left untouched.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import col, delete, select, update
from sqlmodel.ext.asyncio.session import AsyncSession

from app.ai_scanner import ScanFinding
from app.config import get_settings
from app.db import get_engine, session_scope
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
_ACCOUNT = ("github_installation_id", "github_account_login", "github_account_id",
            "github_account_type", "installation_suspended")


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
            logger.info("migration: added teams.github_repo_id")
        if "ix_teams_github_repo_id" not in indexes:
            await conn.execute(text(
                "CREATE UNIQUE INDEX ix_teams_github_repo_id ON teams (github_repo_id)"))
        if indexes.get("ix_teams_github_installation_id"):
            await conn.execute(text("DROP INDEX ix_teams_github_installation_id"))
            await conn.execute(text("CREATE INDEX ix_teams_github_installation_id "
                                    "ON teams (github_installation_id)"))
            logger.info("migration: teams.github_installation_id is no longer unique")


async def split_multi_repo_teams(session: AsyncSession) -> None:
    from app.pipeline import unique_team_slug  # pipeline imports are heavy; keep this lazy

    legacy = {t.id: t for t in (await session.exec(select(Team).where(
        col(Team.github_installation_id).is_not(None),
        col(Team.github_repo_id).is_(None)))).all()}
    if not legacy:
        return
    repos = (await session.exec(select(Repository).where(
        col(Repository.team_id).in_(list(legacy))).order_by(col(Repository.id)))).all()
    groups: dict[int, list[Repository]] = defaultdict(list)
    for repo in repos:
        groups[repo.github_repo_id].append(repo)
    integrations = {i.team_id: i for i in (await session.exec(select(TeamIntegration).where(
        col(TeamIntegration.team_id).in_(list(legacy))))).all()}
    public = get_settings().public_team_slugs

    assigned: dict[int, Team] = {}  # team id -> team now owning one repository
    for repo_id, rows in groups.items():
        # The newest active row is the repository as the current installation knows it.
        canonical = max(rows, key=lambda r: (r.is_active, r.id))
        for dup in rows:
            if dup.id != canonical.id:
                await _merge_repository(session, dup, canonical)
        source = legacy[canonical.team_id]
        candidates = sorted({r.team_id for r in rows} - set(assigned))
        if candidates:
            team = legacy[candidates[0]]  # the oldest team of this repository
        else:
            team = Team(name=canonical.name, slug=f"tmp-{repo_id}")
            session.add(team)
        for field in _ACCOUNT:
            setattr(team, field, getattr(source, field))
        team.name, team.github_repo_id = canonical.name, repo_id
        if team.slug not in public:
            team.slug = f"tmp-{repo_id}"  # free the old slug before choosing a new one
            await session.flush()
            team.slug = await unique_team_slug(session, canonical.owner, canonical.name,
                                               repo_id)
        session.add(team)
        await session.flush()
        assert team.id is not None
        assigned[team.id] = team
        if team.id not in integrations:
            old = next((integrations[r.team_id] for r in rows if r.team_id in integrations),
                       None)
            if old is not None:
                integrations[team.id] = TeamIntegration(
                    team_id=team.id, discord_webhook_url=old.discord_webhook_url,
                    discord_include_warnings=old.discord_include_warnings)
                session.add(integrations[team.id])
        canonical.team_id = team.id
        session.add(canonical)
        await (await session.connection()).execute(update(PushEvent).where(
            col(PushEvent.repository_id) == canonical.id).values(team_id=team.id))
        logger.info("migration: %s -> team %s", canonical.full_name, team.slug)
    await session.flush()

    await _rebuild_scores(session, list(legacy), sorted(set(legacy) | set(assigned)))
    for team_id, team in legacy.items():
        if team_id in assigned:
            continue
        leftover = (await session.exec(select(PushEvent.id).where(
            PushEvent.team_id == team_id))).first()
        if leftover is None:  # every repository moved out: the old account-wide team goes
            await (await session.connection()).execute(delete(TeamIntegration).where(
                col(TeamIntegration.team_id) == team_id))
            await (await session.connection()).execute(delete(Developer).where(
                col(Developer.team_id) == team_id))
            await session.delete(team)
            logger.info("migration: removed emptied team %s", team.slug)
    await session.flush()


async def _merge_repository(session: AsyncSession, dup: Repository,
                            canonical: Repository) -> None:
    """Fold a duplicate row of the same GitHub repository (from an older install) into one."""
    for model in (PushEvent, Finding):
        await (await session.connection()).execute(update(model).where(
            col(model.repository_id) == dup.id).values(repository_id=canonical.id))
    for model in (RepoFile, CodeSymbol, CodeEdge):  # the stale graph of the old install
        await (await session.connection()).execute(delete(model).where(
            col(model.repository_id) == dup.id))
    await session.delete(dup)
    await session.flush()


async def _rebuild_scores(session: AsyncSession, old_team_ids: list[int],
                          team_ids: list[int]) -> None:
    """Replay every scored push, in order, onto per-team developer rows."""
    threshold = get_settings().readability_neutral_threshold
    originals = {d.id: d for d in (await session.exec(select(Developer).where(
        col(Developer.team_id).in_(old_team_ids)))).all()}
    fresh = Developer()
    for dev in originals.values():
        for field in _AGGREGATES:
            setattr(dev, field, getattr(fresh, field))
        session.add(dev)
    devs: dict[tuple[int, str], Developer] = {
        (d.team_id, d.github_login): d for d in originals.values()}
    used: set[int] = set()

    async def developer_for(push: PushEvent) -> Developer:
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
        assert dev.id is not None
        used.add(dev.id)
        return dev

    rows = (await session.exec(
        select(PushEvent, ScoreSnapshot)
        .join(ScoreSnapshot, col(ScoreSnapshot.push_event_id) == col(PushEvent.id))
        .where(col(PushEvent.team_id).in_(team_ids))
        .order_by(col(PushEvent.completed_at), col(PushEvent.id)))).all()
    for push, snap in rows:
        dev = await developer_for(push)
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

    # Unscored pushes (no Python changes, failed scans) still need a developer on their team.
    scored = {push.id for push, _ in rows}
    for push in (await session.exec(select(PushEvent).where(
            col(PushEvent.team_id).in_(team_ids)))).all():
        if push.id not in scored:
            push.developer_id = (await developer_for(push)).id
            session.add(push)

    # Developers left without a push on their team (everything moved elsewhere) are dropped.
    for dev in originals.values():
        if dev.id not in used:
            await session.delete(dev)
    await session.flush()


def _scan_finding(f: Finding) -> ScanFinding:
    return ScanFinding(category=f.category, source=f.source, status=f.status,
                       severity=f.severity, rule_id=f.rule_id, title=f.title,
                       description=f.description, file_path=f.file_path,
                       start_line=f.start_line, end_line=f.end_line, cwe=f.cwe)
