"""Scan orchestration: webhook payload -> graph update -> AI scan -> scoring -> Check Run.

Every public coroutine here is safe to run as a FastAPI background task: it opens its own
DB sessions, never raises (errors are logged and reflected on the push + check run), and
serializes work per repository so two pushes never race on the same project graph.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, insert
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import discord
from app.ai_scanner import AIScanner, ScanFinding, ScanInput, ScanResult
from app.ast_engine import BlastRadius, ProjectGraph, changed_lines_from_patch
from app.config import Settings, get_settings
from app.db import session_scope
from app.enums import (
    CheckConclusion,
    EventType,
    FindingCategory,
    FindingStatus,
    MemberRole,
    ScanStatus,
)
from app.fixer import FixAgent, FixProposal, fixable
from app.github_app import NULL_SHA, GitHubApp, GitHubError
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
from app.scoring import PushScore, apply_push, craft_subscores

logger = logging.getLogger(__name__)

CHECK_NAME = "0 Days Since"


# --------------------------------------------------------------------------------------
# Graph cache & per-repo locks
# --------------------------------------------------------------------------------------


class _GraphCache:
    def __init__(self) -> None:
        self._graphs: OrderedDict[int, ProjectGraph] = OrderedDict()
        self._locks: dict[int, asyncio.Lock] = {}

    def lock(self, repo_id: int) -> asyncio.Lock:
        return self._locks.setdefault(repo_id, asyncio.Lock())

    def get(self, repo_id: int) -> ProjectGraph | None:
        graph = self._graphs.get(repo_id)
        if graph is not None:
            self._graphs.move_to_end(repo_id)
        return graph

    def put(self, repo_id: int, graph: ProjectGraph, capacity: int) -> None:
        if capacity <= 0:
            return
        self._graphs[repo_id] = graph
        self._graphs.move_to_end(repo_id)
        while len(self._graphs) > capacity:
            self._graphs.popitem(last=False)

    def drop(self, repo_id: int) -> None:
        self._graphs.pop(repo_id, None)


graph_cache = _GraphCache()


class _KeyedLocks:
    """One asyncio.Lock per key (the backend runs a single worker process)."""

    def __init__(self) -> None:
        self._locks: dict[object, asyncio.Lock] = {}

    def __call__(self, key: object) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())


# Scans and installation events for one installation run concurrently (one per repository),
# but share the team, repository and developer rows: "select, insert if missing" on those must
# not interleave, or every job after the first dies on a unique-constraint violation.
installation_lock = _KeyedLocks()
# A developer's running scores are read-modify-written once per push, from any repository.
developer_lock = _KeyedLocks()


# --------------------------------------------------------------------------------------
# Job description
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class ScanJob:
    installation_id: int
    repo: dict[str, Any]  # GitHub repository payload
    event_type: EventType
    after_sha: str
    before_sha: str | None
    ref: str | None
    author_login: str
    author_id: int | None = None
    author_avatar: str | None = None
    author_name: str | None = None
    author_email: str | None = None
    commit_message: str = ""
    commit_url: str | None = None
    pr_number: int | None = None
    delivery_id: str | None = None


FIX_BRANCH_PREFIX = "zeroday/fix-"


def is_bot(login: str | None, account_type: str | None = None) -> bool:
    """GitHub Apps and bots (this app's own fix commits, Dependabot, ...) are never scored."""
    return account_type == "Bot" or (login or "").lower().endswith("[bot]")


def job_from_push(payload: dict[str, Any], delivery_id: str | None) -> ScanJob | None:
    """Build a job from a `push` payload, or None if there is nothing to scan."""
    after = payload.get("after") or ""
    if payload.get("deleted") or not after or after == NULL_SHA:
        return None
    if not (payload.get("ref") or "").startswith("refs/heads/"):
        return None  # tags
    head = payload.get("head_commit") or {}
    if not head:
        return None
    sender = payload.get("sender") or {}
    author = head.get("author") or {}
    login = author.get("username") or sender.get("login") or "unknown"
    if payload["ref"].startswith(f"refs/heads/{FIX_BRANCH_PREFIX}") or is_bot(login) or \
            is_bot(sender.get("login"), sender.get("type")):
        return None  # the agent's own fix branches and bot pushes are not people's scores
    same_as_sender = login == sender.get("login")
    before = payload.get("before")
    return ScanJob(
        installation_id=int(payload["installation"]["id"]), repo=payload["repository"],
        event_type=EventType.PUSH, after_sha=after,
        before_sha=None if not before or before == NULL_SHA else before,
        ref=payload.get("ref"), author_login=login,
        author_id=sender.get("id") if same_as_sender else None,
        author_avatar=sender.get("avatar_url") if same_as_sender else None,
        author_name=author.get("name"), author_email=author.get("email"),
        commit_message=head.get("message", ""), commit_url=head.get("url"),
        delivery_id=delivery_id,
    )


def job_from_pull_request(payload: dict[str, Any], delivery_id: str | None) -> ScanJob | None:
    """PRs from the same repo are covered by their `push`; only fork PRs are scanned here."""
    if payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return None
    pr = payload["pull_request"]
    head_repo = (pr.get("head") or {}).get("repo") or {}
    base_repo = (pr.get("base") or {}).get("repo") or {}
    if head_repo.get("id") == base_repo.get("id"):
        return None
    user = pr.get("user") or {}
    if is_bot(user.get("login"), user.get("type")):
        return None
    return ScanJob(
        installation_id=int(payload["installation"]["id"]), repo=payload["repository"],
        event_type=EventType.PULL_REQUEST, after_sha=pr["head"]["sha"],
        before_sha=pr["base"]["sha"], ref=f"refs/pull/{pr['number']}/head",
        author_login=user.get("login", "unknown"), author_id=user.get("id"),
        author_avatar=user.get("avatar_url"), commit_message=pr.get("title", ""),
        commit_url=pr.get("html_url"), pr_number=int(pr["number"]), delivery_id=delivery_id,
    )


# --------------------------------------------------------------------------------------
# Upserts
# --------------------------------------------------------------------------------------


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")[:80] or "team"


async def upsert_team(session: AsyncSession, installation_id: int,
                      account: dict[str, Any]) -> Team:
    team = (await session.exec(select(Team).where(
        Team.github_installation_id == installation_id))).first()
    login = account.get("login") or f"installation-{installation_id}"
    if team is None:
        slug = _slugify(login)
        if (await session.exec(select(Team).where(Team.slug == slug))).first():
            slug = f"{slug}-{installation_id}"
        team = Team(name=login, slug=slug, github_installation_id=installation_id)
        session.add(team)
    team.github_account_login = login
    team.github_account_id = account.get("id")
    team.github_account_type = account.get("type")
    team.installation_suspended = False
    await session.flush()
    return team


async def upsert_repository(session: AsyncSession, team: Team, repo: dict[str, Any]
                            ) -> Repository:
    row = (await session.exec(select(Repository).where(
        Repository.team_id == team.id, Repository.github_repo_id == int(repo["id"])))).first()
    full_name = repo.get("full_name") or f"{repo['owner']['login']}/{repo['name']}"
    owner, _, name = full_name.partition("/")
    if row is None:
        row = Repository(team_id=team.id, github_repo_id=int(repo["id"]), owner=owner,
                         name=name, full_name=full_name)
        session.add(row)
    row.owner, row.name, row.full_name = owner, name, full_name
    row.default_branch = repo.get("default_branch") or row.default_branch or "main"
    row.private = bool(repo.get("private", True))
    row.is_active = True
    await session.flush()
    return row


async def upsert_developer(session: AsyncSession, team: Team, job: ScanJob) -> Developer:
    dev = (await session.exec(select(Developer).where(
        Developer.team_id == team.id, Developer.github_login == job.author_login))).first()
    if dev is None:
        has_members = (await session.exec(select(Developer.id).where(
            Developer.team_id == team.id))).first()
        dev = Developer(team_id=team.id, github_login=job.author_login,
                        role=MemberRole.MEMBER if has_members else MemberRole.OWNER)
        session.add(dev)
    dev.github_id = job.author_id or dev.github_id
    dev.avatar_url = job.author_avatar or dev.avatar_url or \
        f"https://github.com/{job.author_login}.png"
    dev.display_name = dev.display_name or job.author_name
    dev.email = dev.email or job.author_email
    await session.flush()
    return dev


# --------------------------------------------------------------------------------------
# Graph persistence
# --------------------------------------------------------------------------------------


async def load_graph(session: AsyncSession, repo: Repository, settings: Settings
                     ) -> ProjectGraph | None:
    cached = graph_cache.get(repo.id)
    if cached is not None:
        return cached
    rows = (await session.exec(select(RepoFile.path, RepoFile.content).where(
        RepoFile.repository_id == repo.id))).all()
    if not rows:
        return None
    graph = ProjectGraph(max_files=settings.max_python_files,
                         max_file_bytes=settings.max_file_bytes)
    graph.update_files({path: content for path, content in rows})
    graph_cache.put(repo.id, graph, settings.graph_cache_size)
    return graph


async def persist_graph(session: AsyncSession, repo: Repository, graph: ProjectGraph,
                        changed_paths: list[str], removed_paths: list[str], commit_sha: str,
                        blob_shas: dict[str, str] | None = None) -> None:
    """Upsert changed file contents and replace the persisted symbol/edge tables."""
    now = datetime.now(timezone.utc)
    blob_shas = blob_shas or {}
    conn = await session.connection()  # bulk DML on the session's transaction
    if removed_paths:
        await conn.execute(delete(RepoFile).where(col(RepoFile.repository_id) == repo.id,
                                                  col(RepoFile.path).in_(removed_paths)))
    if changed_paths:
        await conn.execute(delete(RepoFile).where(col(RepoFile.repository_id) == repo.id,
                                                  col(RepoFile.path).in_(changed_paths)))
        rows = []
        for path in changed_paths:
            pf = graph.files.get(path)
            if pf is None:
                continue
            rows.append({
                "repository_id": repo.id, "path": path, "blob_sha": blob_shas.get(path),
                "content_sha256": hashlib.sha256(pf.source.encode("utf-8", "replace"))
                .hexdigest(),
                "content": pf.source, "size_bytes": len(pf.source.encode("utf-8", "replace")),
                "parse_error": pf.syntax_error, "last_commit_sha": commit_sha,
                "updated_at": now,
            })
        if rows:
            await conn.execute(insert(RepoFile), rows)

    await conn.execute(delete(CodeEdge).where(col(CodeEdge.repository_id) == repo.id))
    await conn.execute(delete(CodeSymbol).where(col(CodeSymbol.repository_id) == repo.id))
    symbols = [{**r, "repository_id": repo.id, "commit_sha": commit_sha, "updated_at": now}
               for r in graph.symbol_records()]
    edges = [{**r, "repository_id": repo.id} for r in graph.edge_records()]
    for i in range(0, len(symbols), 2000):
        await conn.execute(insert(CodeSymbol), symbols[i:i + 2000])
    for i in range(0, len(edges), 5000):
        await conn.execute(insert(CodeEdge), edges[i:i + 5000])
    stats = graph.stats()
    repo.python_file_count = stats["files"]
    repo.symbol_count = stats["symbols"]
    repo.edge_count = stats["edges"]
    repo.last_scanned_sha = commit_sha


async def _fetch_baseline(gh: GitHubApp, token: str, repo: Repository, ref: str,
                          settings: Settings) -> tuple[dict[str, str], dict[str, str]]:
    entries = await gh.python_tree(token, repo.owner, repo.name, ref,
                                   max_files=settings.max_python_files,
                                   max_bytes=settings.max_file_bytes)
    sources = await gh.fetch_blobs(token, repo.owner, repo.name, entries)
    return sources, dict(entries)


async def build_baseline(installation_id: int, repo_id: int, ref: str | None = None,
                         *, transport: Any = None) -> None:
    """Fetch every .py file of a repository and persist the baseline graph."""
    settings = get_settings()
    async with session_scope() as session:
        repo = await session.get(Repository, repo_id)
        if repo is None:
            return
    async with graph_cache.lock(repo_id):
        try:
            async with GitHubApp(settings, transport=transport) as gh:
                token = await gh.installation_token(installation_id)
                target = ref or repo.default_branch
                sources, blobs = await _fetch_baseline(gh, token, repo, target, settings)
            graph = ProjectGraph.from_sources(sources, max_files=settings.max_python_files,
                                              max_file_bytes=settings.max_file_bytes)
            async with session_scope() as session:
                repo = await session.get(Repository, repo_id)
                assert repo is not None
                await persist_graph(session, repo, graph, list(graph.files), [], target, blobs)
                repo.baseline_commit_sha = target
                repo.baseline_built_at = datetime.now(timezone.utc)
                session.add(repo)
            graph_cache.put(repo_id, graph, settings.graph_cache_size)
            logger.info("baseline for %s: %s", repo.full_name, graph.stats())
        except Exception:
            logger.exception("baseline build failed for repo %s", repo_id)


# --------------------------------------------------------------------------------------
# Installation events
# --------------------------------------------------------------------------------------


async def handle_installation_event(event: str, payload: dict[str, Any], *,
                                    transport: Any = None) -> list[int]:
    """installation / installation_repositories: sync team + repos, build baselines."""
    action = payload.get("action")
    installation = payload["installation"]
    installation_id = int(installation["id"])
    repo_ids: list[int] = []
    async with installation_lock(installation_id), session_scope() as session:
        if event == "installation" and action in {"deleted", "suspend"}:
            team = (await session.exec(select(Team).where(
                Team.github_installation_id == installation_id))).first()
            if team is not None:
                team.installation_suspended = True
                repos = (await session.exec(select(Repository).where(
                    Repository.team_id == team.id))).all()
                for r in repos:
                    r.is_active = False
                    graph_cache.drop(r.id)
                    session.add(r)
                session.add(team)
            return []
        team = await upsert_team(session, installation_id, installation.get("account") or {})
        added = payload.get("repositories") or payload.get("repositories_added") or []
        for removed in payload.get("repositories_removed") or []:
            row = (await session.exec(select(Repository).where(
                Repository.team_id == team.id,
                Repository.github_repo_id == int(removed["id"])))).first()
            if row is not None:
                row.is_active = False
                graph_cache.drop(row.id)
                session.add(row)
        for r in added:
            row = await upsert_repository(session, team, {
                **r, "owner": {"login": (r.get("full_name") or "/").split("/")[0]}})
            repo_ids.append(row.id)
    for repo_id in repo_ids:
        await build_baseline(installation_id, repo_id, transport=transport)
    return repo_ids


# --------------------------------------------------------------------------------------
# Push / PR scanning
# --------------------------------------------------------------------------------------


async def run_scan(job: ScanJob, *, gh_transport: Any = None,
                   scanner: AIScanner | None = None) -> int | None:
    """Full scan of one push. Returns the PushEvent id (None if skipped)."""
    settings = get_settings()
    async with installation_lock(job.installation_id), session_scope() as session:
        if job.delivery_id and (await session.exec(select(PushEvent.id).where(
                PushEvent.delivery_id == job.delivery_id))).first():
            return None  # webhook redelivery
        team = await upsert_team(session, job.installation_id,
                                 job.repo.get("owner") or {})
        repo = await upsert_repository(session, team, job.repo)
        duplicate = (await session.exec(select(PushEvent.id).where(
            PushEvent.repository_id == repo.id, PushEvent.after_sha == job.after_sha,
            PushEvent.status != ScanStatus.FAILED))).first()
        if duplicate:
            return None  # same commit already scanned (e.g. pushed to another branch)
        dev = await upsert_developer(session, team, job)
        push = PushEvent(
            team_id=team.id, repository_id=repo.id, developer_id=dev.id,
            delivery_id=job.delivery_id, event_type=job.event_type, ref=job.ref,
            before_sha=job.before_sha, after_sha=job.after_sha, pr_number=job.pr_number,
            commit_message=job.commit_message[:10_000], commit_url=job.commit_url,
            author_login=job.author_login,
        )
        session.add(push)
        await session.flush()
        push_id, repo_id, dev_id = push.id, repo.id, dev.id

    async with GitHubApp(settings, transport=gh_transport) as gh:
        token: str | None = None
        check_run_id: int | None = None
        details_url = f"{settings.frontend_origin.rstrip('/')}/pushes/{push_id}"
        owner, name = job.repo["full_name"].split("/", 1)
        try:
            token = await gh.installation_token(job.installation_id)
            check_run_id = await gh.create_check_run(
                token, owner, name, job.after_sha, name=CHECK_NAME, details_url=details_url,
                external_id=str(push_id))
            async with session_scope() as session:
                push = await session.get(PushEvent, push_id)
                assert push is not None
                push.check_run_id = check_run_id
                push.status = ScanStatus.IN_PROGRESS
                push.started_at = datetime.now(timezone.utc)
                session.add(push)

            async with graph_cache.lock(repo_id):
                await _scan_locked(gh, token, job, push_id, repo_id, dev_id, settings,
                                   scanner or build_scanner(settings),
                                   owner, name, check_run_id, details_url)
        except Exception as exc:
            logger.exception("scan failed for push %s", push_id)
            async with session_scope() as session:
                push = await session.get(PushEvent, push_id)
                if push is not None:
                    push.status = ScanStatus.FAILED
                    push.error = f"{type(exc).__name__}: {exc}"[:4000]
                    push.completed_at = datetime.now(timezone.utc)
                    session.add(push)
            if token and check_run_id:
                try:
                    await gh.complete_check_run(
                        token, owner, name, check_run_id, conclusion="neutral",
                        title="0 Days Since could not complete the scan",
                        summary=f"The scanner hit an internal error and did not score this "
                                f"push.\n\n`{type(exc).__name__}`", details_url=details_url)
                except GitHubError:
                    logger.exception("could not report scan failure to GitHub")
    return push_id


async def _scan_locked(gh: GitHubApp, token: str, job: ScanJob, push_id: int, repo_id: int,
                       dev_id: int, settings: Settings, scanner: AIScanner, owner: str,
                       name: str, check_run_id: int, details_url: str) -> None:
    # ---- 1. graph + diff -----------------------------------------------------------------
    async with session_scope() as session:
        repo = await session.get(Repository, repo_id)
        assert repo is not None
        graph = await load_graph(session, repo, settings)
        default_branch = repo.default_branch

    baseline_blobs: dict[str, str] = {}
    baseline_paths: list[str] = []
    if graph is None:
        sources, baseline_blobs = await _fetch_baseline(gh, token, repo, job.after_sha, settings)
        graph = ProjectGraph.from_sources(sources, max_files=settings.max_python_files,
                                          max_file_bytes=settings.max_file_bytes)
        baseline_paths = list(graph.files)

    base = job.before_sha or (default_branch if job.ref != f"refs/heads/{default_branch}"
                              else None)
    patches: dict[str, str] = {}
    changed_lines: dict[str, set[int] | None] = {}
    removed: list[str] = []
    new_sources: dict[str, str] = {}
    blob_shas: dict[str, str] = {}
    additions = deletions = 0
    files_changed: list[str] = []

    if base is None:  # first push of a brand new repository: everything is new
        for path in graph.files:
            changed_lines[path] = None
        files_changed = list(graph.files)
    else:
        comparison = await gh.compare(token, owner, name, base, job.after_sha)
        to_fetch: list[tuple[str, str]] = []
        for f in comparison.files:
            if f.previous_path and graph.files.get(f.previous_path) is not None:
                removed.append(f.previous_path)
            if not f.path.endswith(".py"):
                continue
            files_changed.append(f.path)
            additions += f.additions
            deletions += f.deletions
            if f.status == "removed":
                removed.append(f.path)
                continue
            if f.blob_sha:
                to_fetch.append((f.path, f.blob_sha))
                blob_shas[f.path] = f.blob_sha
            if f.patch:
                patches[f.path] = f.patch
                changed_lines[f.path] = changed_lines_from_patch(f.patch)
            else:
                changed_lines[f.path] = None  # binary/huge diff: treat whole file as changed
        new_sources = await gh.fetch_blobs(token, owner, name, to_fetch)

    graph.update_files(new_sources, removed=removed)
    graph_cache.put(repo_id, graph, settings.graph_cache_size)
    changed = {p: lines for p, lines in changed_lines.items() if p in graph.files}

    async with session_scope() as session:
        repo = await session.get(Repository, repo_id)
        assert repo is not None
        await persist_graph(session, repo, graph, sorted(set(new_sources) | set(baseline_paths)),
                            removed, job.after_sha, {**baseline_blobs, **blob_shas})
        if baseline_paths:
            repo.baseline_commit_sha = job.after_sha
            repo.baseline_built_at = datetime.now(timezone.utc)
        session.add(repo)

    # ---- 2. nothing to grade --------------------------------------------------------------
    if not changed:
        async with session_scope() as session:
            push = await session.get(PushEvent, push_id)
            assert push is not None
            push.status = ScanStatus.COMPLETED
            push.conclusion = CheckConclusion.SUCCESS
            push.files_changed = files_changed
            push.completed_at = datetime.now(timezone.utc)
            push.ai_summary = "No Python source changes; push not scored."
            session.add(push)
        await gh.complete_check_run(token, owner, name, check_run_id, conclusion="success",
                                    title="No Python changes to score",
                                    summary="This push does not modify analyzable Python files.",
                                    details_url=details_url)
        return

    # ---- 3. analysis -------------------------------------------------------------------
    t_scan = time.perf_counter()
    radius = graph.blast_radius(changed, hops=settings.blast_radius_hops)
    quality = graph.quality_report(changed)
    result = await scanner.scan(ScanInput(
        graph=graph, changed=changed, radius=radius, quality=quality, patches=patches,
        commit_message=job.commit_message, repo_full_name=job.repo["full_name"],
    ))
    craft = craft_subscores(quality, result.craft_adjustment)
    t_fix = time.perf_counter()
    fixes = await run_fixes(gh, token, owner, name, job, graph, result, settings, scanner)
    timings = {**result.timings, "fixes_ms": int((time.perf_counter() - t_fix) * 1000),
               "analysis_ms": int((time.perf_counter() - t_scan) * 1000)}
    logger.info("push %s timings: %s", push_id,
                " ".join(f"{k}={v}" for k, v in timings.items()))

    # ---- 4. scoring + persistence -------------------------------------------------------
    async with developer_lock(dev_id), session_scope() as session:
        dev = await session.get(Developer, dev_id, with_for_update=True)
        push = await session.get(PushEvent, push_id)
        assert dev is not None and push is not None
        score = apply_push(dev, result.findings, craft,
                           readability_threshold=settings.readability_neutral_threshold)
        verified = result.verified_vulnerabilities
        push.status = ScanStatus.COMPLETED
        push.conclusion = score.conclusion
        push.completed_at = datetime.now(timezone.utc)
        push.files_changed = files_changed
        push.additions, push.deletions = additions, deletions
        for sev in ("critical", "high", "medium", "low"):
            setattr(push, f"vuln_{sev}", sum(1 for f in verified
                                             if f.severity.value.lower() == sev))
        push.push_fault_weight = score.fault_weight
        push.is_faulty = score.is_faulty
        if craft is not None:
            push.docs_score, push.readability_score = craft.docs, craft.readability
            push.type_hints_score, push.craft_push_score = craft.type_hints, craft.total
        push.quality_metrics = {k: v for k, v in quality.to_dict().items() if k != "per_symbol"}
        push.quality_metrics["per_symbol"] = quality.per_symbol[:50]
        push.quality_metrics["ai_notes"] = result.craft_adjustment.notes
        push.security_before, push.security_after = score.security_before, score.security_after
        push.craft_before, push.craft_after = score.craft_before, score.craft_after
        push.composite_before = score.composite_before
        push.composite_after = score.composite_after
        push.points_delta = score.points_delta
        push.ai_summary = result.summary
        push.llm_model = result.model
        push.blast_radius = radius.to_dict()
        push.agent_trace = {
            "investigation": result.agent.to_dict() if result.agent else None,
            "fixes": [f.to_dict() for f in fixes],
            "timings": timings,
        }
        if result.errors:
            push.error = "; ".join(result.errors)[:4000]
        for f in result.findings:
            session.add(Finding(push_event_id=push_id, repository_id=repo_id,
                                **f.to_model_kwargs()))
        session.add(ScoreSnapshot(
            team_id=dev.team_id, developer_id=dev.id, push_event_id=push_id,
            security_score=dev.security_score, craft_score=dev.craft_score,
            composite_score=dev.composite_score, total_pushes=dev.total_pushes,
            faulty_pushes=dev.faulty_pushes, points_delta=score.points_delta,
            is_faulty=score.is_faulty,
        ))
        session.add_all([dev, push])

    # ---- 5. GitHub check -------------------------------------------------------------
    title, summary, text = build_check_output(job, result, score, radius, details_url,
                                              settings)
    text = (text + fix_section(fixes)).strip()[:60_000]
    await gh.complete_check_run(token, owner, name, check_run_id,
                                conclusion=score.conclusion.value, title=title, summary=summary,
                                text=text,
                                annotations=select_annotations(result.findings,
                                                               settings.max_annotations),
                                details_url=details_url)

    # ---- 6. team channel (best-effort, never fails the scan) ----------------------------
    await discord.notify_push(push_id, [f.to_dict() for f in fixes])


# --------------------------------------------------------------------------------------
# Agent auto-fix
# --------------------------------------------------------------------------------------


def build_scanner(settings: Settings) -> AIScanner:
    llm = LLMClient.from_settings(settings)
    return AIScanner(llm, context_chars=settings.llm_context_chars,
                     agent_enabled=settings.agent_enabled,
                     agent_max_steps=settings.agent_max_steps,
                     agent_llm=llm.variant(model=settings.llm_agent_model,
                                           thinking=settings.llm_agent_thinking))


async def run_fixes(gh: GitHubApp, token: str, owner: str, name: str, job: ScanJob,
                    graph: ProjectGraph, result: ScanResult, settings: Settings,
                    scanner: AIScanner) -> list[FixProposal]:
    """Propose + verify a patch per confirmed vulnerability; open PRs for verified ones."""
    if not (settings.agent_fix_enabled and result.ai_used and scanner.llm.available):
        return []
    targets = fixable(result.findings)[:settings.agent_max_fixes]
    if not targets:
        return []
    fixer = FixAgent(scanner.llm)
    branch = (job.ref or "").removeprefix("refs/heads/")
    # PRs only for branch pushes we can write to (not fork pull requests).
    can_open = settings.agent_open_fix_prs and job.event_type is EventType.PUSH and bool(branch)
    # Each fix is proposed and re-verified independently (on its own copy of the graph), so
    # they run concurrently; PRs are then opened one at a time.
    results = await asyncio.gather(*(fixer.propose(graph, f) for f in targets),
                                   return_exceptions=True)
    proposals: list[FixProposal] = []
    for i, (finding, proposal) in enumerate(zip(targets, results, strict=True), start=1):
        if isinstance(proposal, BaseException):
            logger.warning("fix proposal failed: %s", proposal)
            continue
        if proposal is None:
            continue
        if proposal.verified and can_open:
            try:
                proposal.pr_number, proposal.pr_url = await gh.open_pull_request_with_files(
                    token, owner, name, base_branch=branch, base_sha=job.after_sha,
                    branch=f"{FIX_BRANCH_PREFIX}{job.after_sha[:7]}-{i}",
                    files=proposal.new_sources,
                    commit_message=proposal.commit_message,
                    title=f"🛡️ {proposal.commit_message}",
                    body=fix_pr_body(job, finding, proposal))
            except GitHubError as exc:
                proposal.error = f"could not open PR: {exc}"
                logger.warning("fix PR failed: %s", exc)
        proposals.append(proposal)
    return proposals


def fix_pr_body(job: ScanJob, finding: ScanFinding, proposal: FixProposal) -> str:
    return (f"Automated fix proposed by the 0 Days Since Nemotron agent for "
            f"**{finding.title}** ({finding.cwe or finding.rule_id}, {finding.severity.value}) "
            f"introduced in {job.after_sha[:7]}.\n\n**What changed:** {proposal.explanation}"
            f"\n\n**How it was checked:** {proposal.verification}\n\n"
            "Review it like any other PR before merging.")


def fix_section(fixes: list[FixProposal]) -> str:
    if not fixes:
        return ""
    lines = ["", "### 🤖 Agent fixes"]
    for f in fixes:
        if f.pr_url:
            lines.append(f"- ✅ [PR #{f.pr_number}]({f.pr_url}): {f.commit_message}")
        elif f.verified:
            lines.append(f"- ✅ Verified fix ready (see dashboard): {f.commit_message}")
        else:
            lines.append(f"- ⚠️ {f.finding_title}: {f.error or f.verification or 'not verified'}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# Check output
# --------------------------------------------------------------------------------------


def select_annotations(findings: list[ScanFinding], limit: int) -> list[dict[str, Any]]:
    """Verified security first (most severe first), then candidates, then quality."""
    def rank(f: ScanFinding) -> tuple[int, int]:
        if f.category is FindingCategory.SECURITY and f.status is FindingStatus.VERIFIED:
            group = 0
        elif f.category is FindingCategory.SECURITY:
            group = 1
        else:
            group = 2
        return group, -f.severity.rank

    shown = [f for f in findings if f.status is not FindingStatus.REJECTED]
    return [f.to_annotation() for f in sorted(shown, key=rank)[:limit]]


def _fmt_delta(n: int) -> str:
    return f"+{n}" if n > 0 else (f"−{abs(n)}" if n < 0 else "±0")


def build_check_output(job: ScanJob, result: ScanResult, score: PushScore,
                       radius: BlastRadius, details_url: str, settings: Settings
                       ) -> tuple[str, str, str]:
    verified = result.verified_vulnerabilities
    blocking = [f for f in verified if f.severity.blocks_merge]
    delta = _fmt_delta(score.points_delta)
    if score.conclusion is CheckConclusion.FAILURE:
        title = (f"❌ {len(blocking)} blocking vulnerabilit"
                 f"{'y' if len(blocking) == 1 else 'ies'} ({delta} pts)")
    elif score.conclusion is CheckConclusion.NEUTRAL:
        if verified:
            title = f"⚠️ {len(verified)} non-blocking issue(s) to fix ({delta} pts)"
        else:
            title = f"⚠️ Readability below {settings.readability_neutral_threshold:.0f}/300 " \
                    f"({delta} pts)"
    else:
        title = f"✅ Clean push ({delta} pts)"

    lines = [
        f"**@{job.author_login}**: composite **{score.composite_before} → "
        f"{score.composite_after}** ({delta})",
        "",
        "| | Before | After |",
        "|---|---:|---:|",
        f"| 🛡️ Security (0-700) | {score.security_before} | {score.security_after} |",
        f"| ✍️ Code Craft (0-300) | {score.craft_before} | {score.craft_after} |",
        "",
    ]
    if result.summary:
        lines += ["### Summary", result.summary, ""]
    if verified:
        lines += ["### Verified vulnerabilities", "| Severity | CWE | Issue | Location |",
                  "|---|---|---|---|"]
        for f in sorted(verified, key=lambda x: -x.severity.rank):
            lines.append(f"| {f.severity.value} | {f.cwe or '-'} | {f.title} | "
                         f"`{f.file_path}:{f.start_line}` |")
        lines.append("")
    rejected = [f for f in result.findings if f.status is FindingStatus.REJECTED]
    if rejected:
        lines.append(f"_{len(rejected)} candidate(s) were rejected as false positives by the "
                     "skeptic verifier._\n")
    if score.craft is not None:
        c = score.craft
        lines += ["### Code craft for this push",
                  f"Docs & comments **{c.docs:.0f}**/100 · Readability **{c.readability:.0f}**"
                  f"/100 · Type hints & best practices **{c.type_hints:.0f}**/100 → "
                  f"**{c.total:.0f}/300**", ""]
    if radius.entry_points or radius.impacted_files:
        lines += ["### Blast radius",
                  f"{len(radius.seeds)} changed symbol(s), {len(radius.upstream)} upstream "
                  f"caller(s), {len(radius.downstream)} downstream callee(s) across "
                  f"{len(radius.impacted_files)} file(s); {len(radius.entry_points)} entry "
                  "point(s) reach the change.", ""]
    if result.prompt_injection:
        lines += ["> 🚨 This push contains text aimed at the AI reviewer. Verifier rejections "
                  "of deterministic findings were disabled.", ""]
    lines.append(f"[Open the incident view in the ZeroDay dashboard]({details_url})")

    text_lines = []
    if not result.ai_used:
        text_lines.append("AI analysis was unavailable for this scan; deterministic rules "
                          "were applied and cross-file candidates were reported unverified.")
    for f in result.findings:
        if f.category is FindingCategory.SECURITY and f.status is FindingStatus.VERIFIED:
            text_lines.append(f"#### {f.severity.value}: {f.title}\n`{f.file_path}:"
                              f"{f.start_line}`\n\n{f.description}\n\n"
                              f"**Fix:** {f.remediation or 'n/a'}\n")
    return title, "\n".join(lines), "\n".join(text_lines)
