"""Discord notifications: post faulty pushes to a team's channel via an incoming webhook.

A team connects a channel by pasting the channel's webhook URL (Channel settings >
Integrations > Webhooks). Only genuine Discord webhook URLs are accepted, which also keeps this
from being used to make the server call arbitrary URLs. Mentions are disabled on every message,
so commit text can never ping @everyone. Sending never raises: a broken webhook must not fail a
scan, the error is recorded on the integration instead.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlmodel import col, select

from app.config import get_settings
from app.db import session_scope
from app.enums import CheckConclusion, FindingCategory, FindingStatus
from app.models import Developer, Finding, PushEvent, Repository, TeamIntegration

logger = logging.getLogger(__name__)

WEBHOOK_RE = re.compile(
    r"^https://(?:(?:ptb|canary)\.)?(?:discord\.com|discordapp\.com)"
    r"/api(?:/v\d+)?/webhooks/(\d{5,25})/([A-Za-z0-9_-]{20,120})$")

COLOR_BLOCKED = 0xD03B3B
COLOR_WARNED = 0xFAB219
COLOR_TEST = 0xCCF32F
SEVERITY_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
MAX_FINDINGS = 5

# Tests swap this for an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None


def normalize_webhook_url(url: str) -> str:
    """Return the canonical webhook URL or raise ValueError if it is not a Discord webhook."""
    url = url.strip().split("?", 1)[0].rstrip("/")
    m = WEBHOOK_RE.match(url)
    if not m:
        raise ValueError("Paste a Discord webhook URL: https://discord.com/api/webhooks/<id>/<token>")
    return f"https://discord.com/api/webhooks/{m.group(1)}/{m.group(2)}"


def mask_webhook_url(url: str | None) -> str | None:
    if not url:
        return None
    m = WEBHOOK_RE.match(url)
    return f"discord.com/api/webhooks/{m.group(1)}/••••••" if m else "••••••"


async def send(url: str, payload: dict[str, Any]) -> str | None:
    """POST one message. Returns None on success, else a short error string."""
    try:
        async with httpx.AsyncClient(transport=transport, timeout=10) as client:
            res = await client.post(url, json=payload, params={"wait": "true"})
    except httpx.HTTPError as exc:
        return f"Discord unreachable: {type(exc).__name__}"
    if res.status_code in (200, 204):
        return None
    if res.status_code in (401, 404):
        return "Discord rejected this webhook (it may have been deleted). Copy a fresh webhook URL."
    if res.status_code == 429:
        return "Discord rate-limited the webhook; try again shortly."
    return f"Discord returned HTTP {res.status_code}"


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _base(embed: dict[str, Any]) -> dict[str, Any]:
    return {"username": "0 Days Since", "allowed_mentions": {"parse": []}, "embeds": [embed]}


def test_message(team_name: str, dashboard_url: str) -> dict[str, Any]:
    return _base({
        "title": "✅ Channel connected",
        "url": dashboard_url,
        "description": (f"This channel will hear about faulty pushes to "
                        f"**{_clip(team_name, 80)}**: what broke, who pushed it, and how to "
                        "fix it."),
        "color": COLOR_TEST,
        "footer": {"text": "0 Days Since"},
    })


@dataclass(slots=True)
class PushNews:
    """Everything a notification says about one push (built from the database)."""

    push: PushEvent
    repo_full_name: str
    author: str
    findings: list[Finding]
    days_before: int | None  # days-since streak this push ended (None: first incident ever)
    fix_prs: list[dict[str, Any]]


def push_message(news: PushNews, dashboard_url: str) -> dict[str, Any]:
    p = news.push
    blocked = p.conclusion is CheckConclusion.FAILURE
    title_line = (p.commit_message or "").strip().splitlines()[0] if p.commit_message else ""
    branch = (p.ref or "").removeprefix("refs/heads/") or "?"
    head = "🚨 Merge blocked" if blocked else "⚠️ Faulty push"
    fields: list[dict[str, Any]] = []
    if p.is_faulty:
        was = "first incident" if news.days_before is None else (
            f"was {news.days_before} {'day' if news.days_before == 1 else 'days'}")
        fields.append({"name": "Days since last incident", "value": f"**0** ({was})",
                       "inline": True})
    if p.points_delta is not None:
        arrow = "▲" if p.points_delta > 0 else "▼" if p.points_delta < 0 else "•"
        fields.append({"name": "Score", "value": (
            f"{arrow} {p.points_delta:+d} pts ({p.composite_before} → {p.composite_after})"),
            "inline": True})
    if news.findings:
        lines = [f"{SEVERITY_ICON.get(f.severity.value, '•')} **{_clip(f.title, 70)}** · "
                 f"`{_clip(f.file_path, 60)}:{f.start_line}`" for f in news.findings[:MAX_FINDINGS]]
        if len(news.findings) > MAX_FINDINGS:
            lines.append(f"…and {len(news.findings) - MAX_FINDINGS} more")
        fields.append({"name": "What to fix", "value": "\n".join(lines)[:1024]})
    if news.fix_prs:
        fields.append({"name": "🛠 Agent fix", "value": "\n".join(
            f"[PR #{f['pr_number']}]({f['pr_url']}) · verified patch for "
            f"{_clip(f.get('finding_title') or 'the finding', 60)}"
            for f in news.fix_prs)[:1024]})
    return _base({
        "title": _clip(f"{head} · {news.repo_full_name}", 256),
        "url": f"{dashboard_url}/pushes/{p.id}",
        "description": (f"**{_clip(title_line or 'Push', 200)}**\n"
                        f"`{p.after_sha[:7]}` on `{_clip(branch, 60)}` by **@{news.author}**"),
        "color": COLOR_BLOCKED if blocked else COLOR_WARNED,
        "fields": fields,
        "footer": {"text": "0 Days Since · reviewed by Nemotron"},
        "timestamp": (p.completed_at or datetime.now(timezone.utc)).isoformat(),
    })


def should_notify(push: PushEvent, integration: TeamIntegration) -> bool:
    if push.is_faulty:
        return True
    return integration.discord_include_warnings and push.conclusion is CheckConclusion.NEUTRAL


async def notify_push(push_id: int, fixes: list[dict[str, Any]] | None = None) -> bool:
    """Send the push to its team's Discord channel if it qualifies. Never raises."""
    try:
        return await _notify_push(push_id, fixes or [])
    except Exception:  # notification is best-effort; the scan already succeeded
        logger.exception("discord notification failed for push %s", push_id)
        return False


async def _notify_push(push_id: int, fixes: list[dict[str, Any]]) -> bool:
    async with session_scope() as session:
        push = await session.get(PushEvent, push_id)
        if push is None:
            return False
        integration = (await session.exec(select(TeamIntegration).where(
            TeamIntegration.team_id == push.team_id))).first()
        if integration is None or not integration.discord_webhook_url or \
                not should_notify(push, integration):
            return False
        repo = await session.get(Repository, push.repository_id)
        dev = await session.get(Developer, push.developer_id) if push.developer_id else None
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted((await session.exec(select(Finding).where(
            Finding.push_event_id == push.id,
            Finding.category == FindingCategory.SECURITY,
            Finding.status != FindingStatus.REJECTED))).all(),
            key=lambda f: (rank.get(f.severity.value, 9), f.file_path, f.start_line))
        # The streak this push ended: whole days since the team's previous incident.
        prev = (await session.exec(select(PushEvent.completed_at).where(
            PushEvent.team_id == push.team_id, PushEvent.id != push.id,
            PushEvent.is_faulty == True,  # noqa: E712
            col(PushEvent.completed_at).is_not(None))
            .order_by(col(PushEvent.completed_at).desc()).limit(1))).first()
        now = _aware(push.completed_at or datetime.now(timezone.utc))
        days_before = max(0, (now - _aware(prev)).days) if prev else None
        news = PushNews(
            push=push, repo_full_name=repo.full_name if repo else "repository",
            author=(dev.github_login if dev else push.author_login) or "unknown",
            findings=findings, days_before=days_before,
            fix_prs=[f for f in fixes if f.get("pr_url") and f.get("pr_number")])
        url = integration.discord_webhook_url
        integration_id = integration.id

    dashboard = get_settings().frontend_origin.rstrip("/")
    error = await send(url, push_message(news, dashboard))
    async with session_scope() as session:
        row = await session.get(TeamIntegration, integration_id)
        if row is not None:
            row.discord_last_error = error
            if error is None:
                row.discord_last_sent_at = datetime.now(timezone.utc)
            session.add(row)
    if error:
        logger.warning("discord notification for push %s failed: %s", push_id, error)
    return error is None


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
