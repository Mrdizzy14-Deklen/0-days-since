"""Dashboard REST + SSE API consumed by the Next.js frontend.

Auth model: the Next.js server authenticates users with GitHub OAuth, then calls this API
server-to-server with ``Authorization: Bearer <API_TOKEN>``, ``X-GitHub-Login: <login>`` and
``X-GitHub-Installations: <id,id>`` (the GitHub App installations that user can access, looked
up by the Next.js server with the user's own OAuth token). A team is visible when the user can
access its installation, has pushed to it (a Developer row), or the team is listed in
``PUBLIC_TEAMS`` (read-only demo, also for signed-out visitors). When ``API_TOKEN`` is unset
(local development) the API is open.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import case, func, text
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import discord
from app.config import get_settings
from app.db import DAILY_VIEW, get_session, get_session_factory
from app.enums import CheckConclusion, FindingCategory, FindingStatus, ScanStatus
from app.models import (
    Developer,
    Finding,
    PushEvent,
    Repository,
    ScoreSnapshot,
    Team,
    TeamIntegration,
)

router = APIRouter(prefix="/api")
SessionDep = Annotated[AsyncSession, Depends(get_session)]


# --------------------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class Principal:
    login: str | None  # None = signed-out visitor (public teams only)
    open_mode: bool
    installations: frozenset[int] = frozenset()


def _parse_installations(raw: str | None) -> frozenset[int]:
    return frozenset(int(p) for p in (raw or "").split(",")[:200] if p.strip().isdigit())


async def get_principal(authorization: Annotated[str | None, Header()] = None,
                        x_github_login: Annotated[str | None, Header()] = None,
                        x_github_installations: Annotated[str | None, Header()] = None,
                        ) -> Principal:
    token = get_settings().api_token
    installations = _parse_installations(x_github_installations)
    if not token:
        return Principal(login=x_github_login, open_mode=True, installations=installations)
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not supplied or not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid API token")
    return Principal(login=x_github_login or None, open_mode=False,
                     installations=installations if x_github_login else frozenset())


PrincipalDep = Annotated[Principal, Depends(get_principal)]


async def _team_for(session: AsyncSession, slug: str, principal: Principal) -> Team:
    team = (await session.exec(select(Team).where(Team.slug == slug))).first()
    if team is None:
        raise HTTPException(status_code=404, detail="team not found")
    await _require_member(session, team, principal)
    return team


async def _can_view(session: AsyncSession, team: Team, principal: Principal) -> bool:
    if principal.open_mode or team.slug in get_settings().public_team_slugs:
        return True
    if principal.login is None:
        return False
    if team.github_installation_id is not None and \
            team.github_installation_id in principal.installations:
        return True
    member = (await session.exec(select(Developer.id).where(
        Developer.team_id == team.id, Developer.github_login == principal.login))).first()
    return member is not None


async def _require_member(session: AsyncSession, team: Team | int | None,
                          principal: Principal) -> None:
    if isinstance(team, int):
        team = await session.get(Team, team)
    if team is None or not await _can_view(session, team, principal):
        raise HTTPException(status_code=404, detail="team not found")  # do not leak existence


async def _require_editor(session: AsyncSession, slug: str, principal: Principal) -> Team:
    """Settings changes: a signed-in member of the team (public read-only access is not enough)."""
    team = await _team_for(session, slug, principal)
    if principal.open_mode:
        return team
    is_member = principal.login is not None and (
        (team.github_installation_id is not None
         and team.github_installation_id in principal.installations)
        or (await session.exec(select(Developer.id).where(
            Developer.team_id == team.id, Developer.github_login == principal.login))).first()
        is not None)
    if not is_member:
        raise HTTPException(status_code=403, detail="only team members can change settings")
    return team


# --------------------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------------------


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def developer_json(d: Developer, rank: int | None = None) -> dict[str, Any]:
    return {
        "id": d.id, "rank": rank, "github_login": d.github_login,
        "display_name": d.display_name or d.github_login, "avatar_url": d.avatar_url,
        "role": d.role.value, "composite_score": d.composite_score,
        "security_score": d.security_score, "craft_score": d.craft_score,
        "total_pushes": d.total_pushes, "faulty_pushes": d.faulty_pushes,
        "fault_ratio": round(d.fault_ratio, 4), "weighted_fault_sum": d.weighted_fault_sum,
        "clean_streak": d.clean_streak, "best_clean_streak": d.best_clean_streak,
        "top_cwe": d.top_cwe, "top_smell": d.top_smell, "cwe_counts": d.cwe_counts,
        "smell_counts": d.smell_counts,
        "craft_breakdown": {
            "docs": round(d.craft_docs_sum / d.craft_samples, 1) if d.craft_samples else None,
            "readability": round(d.craft_readability_sum / d.craft_samples, 1)
            if d.craft_samples else None,
            "type_hints": round(d.craft_types_sum / d.craft_samples, 1)
            if d.craft_samples else None,
        },
        "last_push_at": _iso(d.last_push_at),
    }


def push_json(p: PushEvent, dev: Developer | None, repo: Repository | None) -> dict[str, Any]:
    return {
        "id": p.id, "event_type": p.event_type.value, "ref": p.ref,
        "branch": (p.ref or "").removeprefix("refs/heads/"), "before_sha": p.before_sha,
        "after_sha": p.after_sha, "short_sha": p.after_sha[:7], "pr_number": p.pr_number,
        "commit_message": p.commit_message, "commit_url": p.commit_url,
        "status": p.status.value, "conclusion": p.conclusion.value if p.conclusion else None,
        "points_delta": p.points_delta, "composite_before": p.composite_before,
        "composite_after": p.composite_after, "security_before": p.security_before,
        "security_after": p.security_after, "craft_before": p.craft_before,
        "craft_after": p.craft_after, "craft_push_score": p.craft_push_score,
        "docs_score": p.docs_score, "readability_score": p.readability_score,
        "type_hints_score": p.type_hints_score,
        "vulns": {"critical": p.vuln_critical, "high": p.vuln_high, "medium": p.vuln_medium,
                  "low": p.vuln_low},
        "is_faulty": p.is_faulty, "ai_summary": p.ai_summary, "llm_model": p.llm_model,
        "files_changed": p.files_changed, "additions": p.additions, "deletions": p.deletions,
        "error": p.error, "created_at": _iso(p.created_at), "completed_at": _iso(p.completed_at),
        "developer": {"id": dev.id, "github_login": dev.github_login,
                      "avatar_url": dev.avatar_url} if dev else None,
        "repository": {"id": repo.id, "full_name": repo.full_name} if repo else None,
    }


def team_ref(t: Team | None) -> dict[str, Any] | None:
    return {"id": t.id, "slug": t.slug, "name": t.name} if t else None


def finding_json(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "category": f.category.value, "source": f.source.value,
        "status": f.status.value, "severity": f.severity.value, "rule_id": f.rule_id,
        "cwe": f.cwe, "title": f.title, "description": f.description,
        "remediation": f.remediation, "file_path": f.file_path, "start_line": f.start_line,
        "end_line": f.end_line, "symbol_node_id": f.symbol_node_id,
        "confidence": f.confidence, "verifier_reasoning": f.verifier_reasoning,
        "taint_flow": f.taint_flow, "counted_in_score": f.counted_in_score,
    }


async def _push_rows(session: AsyncSession, team_id: int, *, limit: int,
                     before_id: int | None = None, after_id: int | None = None,
                     ids: list[int] | None = None) -> list[dict[str, Any]]:
    stmt = (select(PushEvent, Developer, Repository)
            .join(Developer, col(PushEvent.developer_id) == col(Developer.id), isouter=True)
            .join(Repository, col(PushEvent.repository_id) == col(Repository.id))
            .where(PushEvent.team_id == team_id))
    if before_id is not None:
        stmt = stmt.where(col(PushEvent.id) < before_id)
    if after_id is not None:
        stmt = stmt.where(col(PushEvent.id) > after_id)
    if ids is not None:
        stmt = stmt.where(col(PushEvent.id).in_(ids))
    stmt = stmt.order_by(col(PushEvent.id).desc()).limit(limit)
    return [push_json(p, d, r) for p, d, r in (await session.exec(stmt)).all()]


# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------


@router.get("/teams")
async def list_teams(session: SessionDep, principal: PrincipalDep) -> list[dict[str, Any]]:
    public = get_settings().public_team_slugs
    teams = (await session.exec(select(Team).order_by(Team.name))).all()
    if not principal.open_mode or principal.login:
        member_ids = set((await session.exec(select(Developer.team_id).where(
            Developer.github_login == principal.login))).all()) if principal.login else set()
        teams = [t for t in teams if t.slug in public or t.id in member_ids
                 or (principal.login is not None
                     and t.github_installation_id in principal.installations)]
    return [{"id": t.id, "slug": t.slug, "name": t.name, "account": t.github_account_login,
             "installed": t.github_installation_id is not None and not t.installation_suspended,
             "public": t.slug in public}
            for t in teams]


@router.get("/teams/{slug}/leaderboard")
async def leaderboard(slug: str, session: SessionDep, principal: PrincipalDep
                      ) -> dict[str, Any]:
    team = await _team_for(session, slug, principal)
    devs = (await session.exec(select(Developer).where(Developer.team_id == team.id).order_by(
        col(Developer.composite_score).desc(), col(Developer.clean_streak).desc(),
        Developer.github_login))).all()
    return {"team": team_ref(team),
            "developers": [developer_json(d, i) for i, d in enumerate(devs, start=1)]}


@router.get("/teams/{slug}/stats")
async def team_stats(slug: str, session: SessionDep, principal: PrincipalDep
                     ) -> dict[str, Any]:
    team = await _team_for(session, slug, principal)
    totals = (await session.exec(select(
        func.count(col(PushEvent.id)),
        func.sum(case((col(PushEvent.is_faulty), 1), else_=0)),
    ).where(PushEvent.team_id == team.id, PushEvent.status == ScanStatus.COMPLETED))).one()
    blocked = (await session.exec(select(func.count(col(PushEvent.id))).where(
        PushEvent.team_id == team.id,
        PushEvent.conclusion == CheckConclusion.FAILURE))).one()
    cwe_rows = (await session.exec(
        select(Finding.cwe, func.count(col(Finding.id)))
        .join(PushEvent, col(Finding.push_event_id) == col(PushEvent.id))
        .where(PushEvent.team_id == team.id, col(Finding.counted_in_score).is_(True),
               col(Finding.cwe).is_not(None))
        .group_by(Finding.cwe).order_by(func.count(col(Finding.id)).desc()).limit(5))).all()
    rejected = (await session.exec(
        select(func.count(col(Finding.id)))
        .join(PushEvent, col(Finding.push_event_id) == col(PushEvent.id))
        .where(PushEvent.team_id == team.id,
               Finding.status == FindingStatus.REJECTED))).one()
    repos = (await session.exec(select(Repository).where(
        Repository.team_id == team.id, col(Repository.is_active).is_(True)))).all()
    return {
        "total_pushes": totals[0] or 0, "faulty_pushes": int(totals[1] or 0),
        "blocked_merges": blocked, "false_positives_rejected": rejected,
        "top_cwes": [{"cwe": c, "count": n} for c, n in cwe_rows],
        "repositories": [{"id": r.id, "full_name": r.full_name, "files": r.python_file_count,
                          "symbols": r.symbol_count, "edges": r.edge_count,
                          "last_scanned_sha": r.last_scanned_sha} for r in repos],
    }


@router.get("/teams/{slug}/pushes")
async def team_pushes(slug: str, session: SessionDep, principal: PrincipalDep,
                      limit: Annotated[int, Query(ge=1, le=200)] = 50,
                      before_id: int | None = None) -> list[dict[str, Any]]:
    team = await _team_for(session, slug, principal)
    return await _push_rows(session, team.id, limit=limit, before_id=before_id)


@router.get("/teams/{slug}/trends")
async def team_trends(slug: str, session: SessionDep, principal: PrincipalDep,
                      days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict[str, Any]:
    team = await _team_for(session, slug, principal)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await session.exec(
        select(ScoreSnapshot, Developer.github_login)
        .join(Developer, col(ScoreSnapshot.developer_id) == col(Developer.id))
        .where(ScoreSnapshot.team_id == team.id, col(ScoreSnapshot.recorded_at) >= since)
        .order_by(col(ScoreSnapshot.recorded_at)))).all()
    series: dict[str, list[dict[str, Any]]] = {}
    for snap, login in rows:
        series.setdefault(login, []).append({
            "t": _iso(snap.recorded_at), "composite": snap.composite_score,
            "security": snap.security_score, "craft": snap.craft_score,
            "delta": snap.points_delta, "push_event_id": snap.push_event_id,
        })
    return {"days": days, "series": series}


@router.get("/teams/{slug}/daily")
async def team_daily(slug: str, session: SessionDep, principal: PrincipalDep,
                     days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict[str, Any]:
    """Pushes, faulty pushes and score per day.

    On Tiger Data / TimescaleDB this reads the ``team_daily_scores`` continuous aggregate,
    which the database keeps up to date; elsewhere the same numbers are computed here.
    """
    team = await _team_for(session, slug, principal)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conn = await session.connection()
    if conn.dialect.name == "postgresql" and get_settings().enable_timescale:
        try:
            async with conn.begin_nested():
                rows = (await conn.execute(text(
                    f"SELECT day, pushes, faulty_pushes, net_points, avg_composite, "
                    f"min_composite, max_composite FROM {DAILY_VIEW} "
                    "WHERE team_id = :team AND day >= :since ORDER BY day"),
                    {"team": team.id, "since": since})).all()
            return {"days": days, "source": "timescale_continuous_aggregate",
                    "series": [{"day": _iso(r[0]), "pushes": int(r[1]),
                                "faulty_pushes": int(r[2] or 0), "net_points": int(r[3] or 0),
                                "avg_composite": round(float(r[4]), 1),
                                "min_composite": int(r[5]), "max_composite": int(r[6])}
                               for r in rows]}
        except Exception:  # aggregate missing (no Timescale): fall through
            pass
    snaps = (await session.exec(select(ScoreSnapshot).where(
        ScoreSnapshot.team_id == team.id, col(ScoreSnapshot.recorded_at) >= since)
        .order_by(col(ScoreSnapshot.recorded_at)))).all()
    buckets: dict[str, list[ScoreSnapshot]] = {}
    for snap in snaps:
        ts = snap.recorded_at if snap.recorded_at.tzinfo else \
            snap.recorded_at.replace(tzinfo=timezone.utc)
        day = ts.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets.setdefault(day.isoformat(), []).append(snap)
    return {"days": days, "source": "computed", "series": [
        {"day": day, "pushes": len(group), "faulty_pushes": sum(g.is_faulty for g in group),
         "net_points": sum(g.points_delta for g in group),
         "avg_composite": round(sum(g.composite_score for g in group) / len(group), 1),
         "min_composite": min(g.composite_score for g in group),
         "max_composite": max(g.composite_score for g in group)}
        for day, group in buckets.items()]}


@router.get("/developers/{developer_id}")
async def developer_detail(developer_id: int, session: SessionDep, principal: PrincipalDep,
                           days: Annotated[int, Query(ge=1, le=365)] = 90) -> dict[str, Any]:
    dev = await session.get(Developer, developer_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="developer not found")
    await _require_member(session, dev.team_id, principal)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    snaps = (await session.exec(select(ScoreSnapshot).where(
        ScoreSnapshot.developer_id == dev.id, col(ScoreSnapshot.recorded_at) >= since)
        .order_by(col(ScoreSnapshot.recorded_at)))).all()
    pushes = (await session.exec(select(PushEvent.id).where(
        PushEvent.developer_id == dev.id).order_by(col(PushEvent.id).desc()).limit(20))).all()
    return {
        "team": team_ref(await session.get(Team, dev.team_id)),
        "developer": developer_json(dev),
        "history": [{"t": _iso(s.recorded_at), "composite": s.composite_score,
                     "security": s.security_score, "craft": s.craft_score,
                     "delta": s.points_delta, "push_event_id": s.push_event_id} for s in snaps],
        "recent_pushes": await _push_rows(session, dev.team_id, limit=20, ids=list(pushes)),
    }


@router.get("/pushes/{push_id}")
async def push_detail(push_id: int, session: SessionDep, principal: PrincipalDep
                      ) -> dict[str, Any]:
    push = await session.get(PushEvent, push_id)
    if push is None:
        raise HTTPException(status_code=404, detail="push not found")
    await _require_member(session, push.team_id, principal)
    dev = await session.get(Developer, push.developer_id) if push.developer_id else None
    repo = await session.get(Repository, push.repository_id)
    findings = (await session.exec(select(Finding).where(
        Finding.push_event_id == push.id).order_by(col(Finding.id)))).all()
    sec_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns = sorted((f for f in findings if f.category is FindingCategory.SECURITY),
                   key=lambda f: (f.status is not FindingStatus.VERIFIED,
                                  sec_rank[f.severity.value]))
    quality = [f for f in findings if f.category is FindingCategory.QUALITY]
    radius = push.blast_radius or {}
    modules: dict[str, dict[str, Any]] = {}
    for node in radius.get("nodes", []):
        entry = modules.setdefault(node["file_path"], {
            "file_path": node["file_path"], "roles": set(), "symbols": 0, "sinks": set(),
            "entry_points": 0})
        entry["roles"].add(node["role"])
        entry["symbols"] += 1
        entry["entry_points"] += int(bool(node.get("is_entry_point")))
        entry["sinks"].update(s["kind"] for s in node.get("sinks", []))
    flagged_files = {f.file_path for f in vulns if f.counted_in_score}
    for flow_finding in vulns:
        for step in flow_finding.taint_flow or []:
            if flow_finding.counted_in_score:
                flagged_files.add(step.get("file"))
    incident_scope = sorted(
        ({**m, "roles": sorted(m["roles"]), "sinks": sorted(m["sinks"]),
          "compromised": m["file_path"] in flagged_files} for m in modules.values()),
        key=lambda m: (not m["compromised"], m["file_path"]))
    return {
        "team": team_ref(await session.get(Team, push.team_id)),
        "push": push_json(push, dev, repo),
        "vulnerabilities": [finding_json(f) for f in vulns],
        "quality_findings": [finding_json(f) for f in quality],
        "quality_metrics": push.quality_metrics,
        "blast_radius": radius,
        "incident_scope": incident_scope,
        "agent": push.agent_trace or {},
    }


@router.get("/teams/{slug}/stream")
async def push_stream(slug: str, request: Request, principal: PrincipalDep,
                      last_event_id: Annotated[str | None, Header()] = None) -> StreamingResponse:
    """Server-sent events for the live push feed (new pushes + status transitions)."""
    async with get_session_factory()() as session:
        team = await _team_for(session, slug, principal)
        team_id = team.id

    async def events() -> AsyncIterator[str]:
        seen: dict[int, tuple[str, str | None]] = {}
        cursor = int(last_event_id) if (last_event_id or "").isdigit() else None
        first = True
        while not await request.is_disconnected():
            async with get_session_factory()() as session:
                rows = await _push_rows(session, team_id, limit=30)
            for row in reversed(rows):
                state = (row["status"], row["conclusion"])
                prev = seen.get(row["id"])
                seen[row["id"]] = state
                if first and (cursor is None or row["id"] <= cursor):
                    continue  # client already has these
                if prev != state:
                    yield f"id: {row['id']}\nevent: push\ndata: {json.dumps(row)}\n\n"
            if first:
                yield "event: ready\ndata: {}\n\n"
            first = False
            yield ": keep-alive\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------------------
# Integrations (Discord)
# --------------------------------------------------------------------------------------


class DiscordSettings(BaseModel):
    webhook_url: str | None = Field(default=None, max_length=300)  # None = keep current
    include_warnings: bool = False


async def _integration(session: AsyncSession, team_id: int) -> TeamIntegration | None:
    return (await session.exec(select(TeamIntegration).where(
        TeamIntegration.team_id == team_id))).first()


def _integration_json(row: TeamIntegration | None, can_edit: bool) -> dict[str, Any]:
    url = row.discord_webhook_url if row else None
    return {"can_edit": can_edit, "discord": {
        "connected": bool(url),
        "webhook": discord.mask_webhook_url(url),
        "include_warnings": bool(row and row.discord_include_warnings),
        "last_sent_at": _iso(row.discord_last_sent_at) if row else None,
        "last_error": row.discord_last_error if row else None,
    }}


@router.get("/teams/{slug}/integrations")
async def get_integrations(slug: str, session: SessionDep, principal: PrincipalDep
                           ) -> dict[str, Any]:
    team = await _team_for(session, slug, principal)
    try:
        await _require_editor(session, slug, principal)
        can_edit = True
    except HTTPException:
        can_edit = False
    return _integration_json(await _integration(session, team.id), can_edit)


@router.put("/teams/{slug}/integrations/discord")
async def put_discord(slug: str, body: DiscordSettings, session: SessionDep,
                      principal: PrincipalDep) -> dict[str, Any]:
    team = await _require_editor(session, slug, principal)
    row = await _integration(session, team.id) or TeamIntegration(team_id=team.id)
    if body.webhook_url is not None:
        try:
            url = discord.normalize_webhook_url(body.webhook_url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        error = await discord.send(url, discord.test_message(
            team.name, f"{get_settings().frontend_origin.rstrip('/')}/teams/{team.slug}"))
        if error:
            raise HTTPException(status_code=422, detail=error)
        row.discord_webhook_url = url
        row.discord_last_error = None
        row.discord_last_sent_at = datetime.now(timezone.utc)
    elif not row.discord_webhook_url:
        raise HTTPException(status_code=422, detail="Paste a Discord webhook URL first")
    row.discord_include_warnings = body.include_warnings
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _integration_json(row, True)


@router.post("/teams/{slug}/integrations/discord/test")
async def test_discord(slug: str, session: SessionDep, principal: PrincipalDep
                       ) -> dict[str, Any]:
    team = await _require_editor(session, slug, principal)
    row = await _integration(session, team.id)
    if row is None or not row.discord_webhook_url:
        raise HTTPException(status_code=404, detail="Discord is not connected")
    error = await discord.send(row.discord_webhook_url, discord.test_message(
        team.name, f"{get_settings().frontend_origin.rstrip('/')}/teams/{team.slug}"))
    row.discord_last_error = error
    if error is None:
        row.discord_last_sent_at = datetime.now(timezone.utc)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    if error:
        raise HTTPException(status_code=502, detail=error)
    return _integration_json(row, True)


@router.delete("/teams/{slug}/integrations/discord")
async def delete_discord(slug: str, session: SessionDep, principal: PrincipalDep
                         ) -> dict[str, Any]:
    team = await _require_editor(session, slug, principal)
    row = await _integration(session, team.id)
    if row is not None:
        row.discord_webhook_url = None
        row.discord_last_error = None
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return _integration_json(row, True)
