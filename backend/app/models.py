"""PostgreSQL / Tiger Data (TimescaleDB) data model for ZeroDay Score.

Tenancy: every row hangs off a `Team` (one GitHub App installation == one team).

Tables
------
- teams            : tenant + GitHub App installation
- team_integrations: per-team notification settings (Discord webhook)
- repositories     : connected repos and their baseline/scan state
- repo_files       : latest known content of every analyzable .py file (lets us
                     rebuild the whole-project call graph without re-downloading the repo)
- developers       : per-team developer profile + running score aggregates
- push_events      : one row per scanned push / PR synchronize (the live feed)
- findings         : vulnerabilities & readability issues attached to a push
- code_symbols     : persisted nodes of the project call graph
- code_edges       : persisted edges of the project call graph
- score_snapshots  : time-series of developer scores (Timescale hypertable) for trend charts

Note: no `from __future__ import annotations` here; SQLModel resolves field types at
class-creation time.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from app.enums import (
    CheckConclusion,
    EdgeKind,
    EventType,
    FindingCategory,
    FindingSource,
    FindingStatus,
    MemberRole,
    ScanStatus,
    Severity,
    SymbolKind,
)

# Starting scores for a brand-new developer.
MAX_SECURITY_SCORE = 700
MAX_CRAFT_SCORE = 300
MAX_COMPOSITE_SCORE = MAX_SECURITY_SCORE + MAX_CRAFT_SCORE


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _enum(enum_cls: type[enum.Enum]) -> sa.Enum:
    """Store enums as validated VARCHARs (by value) so adding members needs no PG enum migration."""
    return sa.Enum(
        enum_cls,
        native_enum=False,
        length=32,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


def _json() -> sa.types.TypeEngine:
    """JSONB on PostgreSQL, plain JSON elsewhere (e.g. SQLite in tests)."""
    return sa.JSON().with_variant(JSONB(), "postgresql")


def _tz() -> sa.DateTime:
    return sa.DateTime(timezone=True)


# --------------------------------------------------------------------------------------
# Tenancy
# --------------------------------------------------------------------------------------


class Team(SQLModel, table=True):
    """A tenant. Created on sign-up or automatically on `installation.created`."""

    __tablename__ = "teams"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=200)
    slug: str = Field(max_length=100, unique=True, index=True)

    github_installation_id: int | None = Field(
        default=None, sa_type=sa.BigInteger, unique=True, index=True
    )
    github_account_login: str | None = Field(default=None, max_length=100)
    github_account_id: int | None = Field(default=None, sa_type=sa.BigInteger)
    github_account_type: str | None = Field(default=None, max_length=20)  # "User" | "Organization"
    installation_suspended: bool = Field(default=False)

    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class TeamIntegration(SQLModel, table=True):
    """Per-team notification settings (one row per team). The Discord webhook URL is a secret:
    the API only ever returns it masked."""

    __tablename__ = "team_integrations"

    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="teams.id", unique=True, index=True)
    discord_webhook_url: str | None = Field(default=None, max_length=300)
    discord_include_warnings: bool = Field(default=False)
    discord_last_sent_at: datetime | None = Field(default=None, sa_type=_tz())
    discord_last_error: str | None = Field(default=None, max_length=500)

    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class Repository(SQLModel, table=True):
    __tablename__ = "repositories"
    __table_args__ = (sa.UniqueConstraint("team_id", "github_repo_id", name="uq_repo_team_gh"),)

    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="teams.id", index=True, ondelete="CASCADE")

    github_repo_id: int = Field(sa_type=sa.BigInteger, index=True)
    owner: str = Field(max_length=100)
    name: str = Field(max_length=100)
    full_name: str = Field(max_length=201, index=True)
    default_branch: str = Field(default="main", max_length=255)
    private: bool = Field(default=True)
    is_active: bool = Field(default=True)

    # Baseline graph state
    baseline_commit_sha: str | None = Field(default=None, max_length=40)
    baseline_built_at: datetime | None = Field(default=None, sa_type=_tz())
    last_scanned_sha: str | None = Field(default=None, max_length=40)
    python_file_count: int = Field(default=0)
    symbol_count: int = Field(default=0)
    edge_count: int = Field(default=0)

    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class RepoFile(SQLModel, table=True):
    """Latest content of each analyzable Python file, used to rebuild the graph incrementally."""

    __tablename__ = "repo_files"
    __table_args__ = (sa.UniqueConstraint("repository_id", "path", name="uq_repo_file_path"),)

    id: int | None = Field(default=None, primary_key=True)
    repository_id: int = Field(foreign_key="repositories.id", index=True, ondelete="CASCADE")
    path: str = Field(max_length=1024)
    blob_sha: str | None = Field(default=None, max_length=40)
    content_sha256: str = Field(max_length=64)
    content: str = Field(sa_type=sa.Text)
    size_bytes: int = Field(default=0)
    parse_error: str | None = Field(default=None, sa_type=sa.Text)
    last_commit_sha: str | None = Field(default=None, max_length=40)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


# --------------------------------------------------------------------------------------
# Developers & scoring aggregates
# --------------------------------------------------------------------------------------


class Developer(SQLModel, table=True):
    """Per-team developer profile and the running aggregates behind the leaderboard.

    Security score (0-700):
        fault_rate     = min(1, weighted_fault_sum / max(1, total_pushes))
        security_score = round(700 * (1 - fault_rate))

    Craft score (0-300): rolling average of the per-push docs/readability/type-hint
    sub-scores (each 0-100). The `craft_*_sum` + `craft_samples` columns hold the
    running totals so the average is exact and cheap to update.
    """

    __tablename__ = "developers"
    __table_args__ = (
        sa.UniqueConstraint("team_id", "github_login", name="uq_dev_team_login"),
        sa.Index("ix_dev_team_composite", "team_id", "composite_score"),
    )

    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="teams.id", index=True, ondelete="CASCADE")

    github_login: str = Field(max_length=100)
    github_id: int | None = Field(default=None, sa_type=sa.BigInteger, index=True)
    display_name: str | None = Field(default=None, max_length=200)
    email: str | None = Field(default=None, max_length=320)
    avatar_url: str | None = Field(default=None, max_length=500)
    role: MemberRole = Field(default=MemberRole.MEMBER, sa_type=_enum(MemberRole))
    linked_dashboard_account: bool = Field(default=False)  # signed in via GitHub OAuth

    # Security aggregates
    total_pushes: int = Field(default=0)
    faulty_pushes: int = Field(default=0)
    weighted_fault_sum: float = Field(default=0.0)
    security_score: int = Field(default=MAX_SECURITY_SCORE)

    # Craft aggregates
    craft_samples: int = Field(default=0)
    craft_docs_sum: float = Field(default=0.0)
    craft_readability_sum: float = Field(default=0.0)
    craft_types_sum: float = Field(default=0.0)
    craft_score: int = Field(default=MAX_CRAFT_SCORE)

    composite_score: int = Field(default=MAX_COMPOSITE_SCORE)

    # Streaks & badges
    clean_streak: int = Field(default=0)
    best_clean_streak: int = Field(default=0)
    cwe_counts: dict[str, int] = Field(default_factory=dict, sa_type=_json())
    smell_counts: dict[str, int] = Field(default_factory=dict, sa_type=_json())
    top_cwe: str | None = Field(default=None, max_length=32)
    top_smell: str | None = Field(default=None, max_length=64)

    last_push_at: datetime | None = Field(default=None, sa_type=_tz())
    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )

    @property
    def fault_ratio(self) -> float:
        return self.faulty_pushes / self.total_pushes if self.total_pushes else 0.0


# --------------------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------------------


class PushEvent(SQLModel, table=True):
    """One scanned push / pull_request synchronize. Drives the Live Push & Incident Feed."""

    __tablename__ = "push_events"
    __table_args__ = (
        sa.Index("ix_push_team_created", "team_id", "created_at"),
        sa.Index("ix_push_repo_after", "repository_id", "after_sha"),
    )

    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="teams.id", index=True, ondelete="CASCADE")
    repository_id: int = Field(foreign_key="repositories.id", index=True, ondelete="CASCADE")
    developer_id: int | None = Field(
        default=None, foreign_key="developers.id", index=True, ondelete="SET NULL"
    )

    # GitHub identifiers
    delivery_id: str | None = Field(default=None, max_length=64, unique=True)  # X-GitHub-Delivery
    event_type: EventType = Field(default=EventType.PUSH, sa_type=_enum(EventType))
    ref: str | None = Field(default=None, max_length=255)
    before_sha: str | None = Field(default=None, max_length=40)
    after_sha: str = Field(max_length=40)
    pr_number: int | None = Field(default=None)
    commit_message: str = Field(default="", sa_type=sa.Text)
    commit_url: str | None = Field(default=None, max_length=500)
    author_login: str | None = Field(default=None, max_length=100)
    check_run_id: int | None = Field(default=None, sa_type=sa.BigInteger)

    # Scan lifecycle
    status: ScanStatus = Field(default=ScanStatus.QUEUED, sa_type=_enum(ScanStatus))
    conclusion: CheckConclusion | None = Field(default=None, sa_type=_enum(CheckConclusion))
    error: str | None = Field(default=None, sa_type=sa.Text)
    started_at: datetime | None = Field(default=None, sa_type=_tz())
    completed_at: datetime | None = Field(default=None, sa_type=_tz())

    # Diff
    files_changed: list[str] = Field(default_factory=list, sa_type=_json())
    additions: int = Field(default=0)
    deletions: int = Field(default=0)

    # Vulnerability results
    vuln_critical: int = Field(default=0)
    vuln_high: int = Field(default=0)
    vuln_medium: int = Field(default=0)
    vuln_low: int = Field(default=0)
    push_fault_weight: float = Field(default=0.0)  # sum of w_i for this push
    is_faulty: bool = Field(default=False)

    # Craft results for this push (each 0-100, total 0-300)
    docs_score: float | None = Field(default=None)
    readability_score: float | None = Field(default=None)
    type_hints_score: float | None = Field(default=None)
    craft_push_score: float | None = Field(default=None)
    quality_metrics: dict[str, Any] = Field(default_factory=dict, sa_type=_json())

    # Score movement (developer totals before/after this push)
    security_before: int | None = Field(default=None)
    security_after: int | None = Field(default=None)
    craft_before: int | None = Field(default=None)
    craft_after: int | None = Field(default=None)
    composite_before: int | None = Field(default=None)
    composite_after: int | None = Field(default=None)
    points_delta: int = Field(default=0)

    # AI output and the cross-file slice used for the blast-radius viewer
    ai_summary: str | None = Field(default=None, sa_type=sa.Text)
    llm_model: str | None = Field(default=None, max_length=200)
    blast_radius: dict[str, Any] = Field(default_factory=dict, sa_type=_json())
    # Nemotron agent: {"investigation": {plan, steps, ...}, "fixes": [FixProposal...]}
    agent_trace: dict[str, Any] = Field(default_factory=dict, sa_type=_json())

    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)


class Finding(SQLModel, table=True):
    """A vulnerability or readability issue attached to a push (and a GitHub annotation)."""

    __tablename__ = "findings"
    __table_args__ = (sa.Index("ix_finding_push_status", "push_event_id", "status"),)

    id: int | None = Field(default=None, primary_key=True)
    push_event_id: int = Field(foreign_key="push_events.id", index=True, ondelete="CASCADE")
    repository_id: int = Field(foreign_key="repositories.id", index=True, ondelete="CASCADE")

    category: FindingCategory = Field(sa_type=_enum(FindingCategory))
    source: FindingSource = Field(sa_type=_enum(FindingSource))
    status: FindingStatus = Field(default=FindingStatus.CANDIDATE, sa_type=_enum(FindingStatus))
    severity: Severity = Field(sa_type=_enum(Severity))

    rule_id: str = Field(max_length=64)
    cwe: str | None = Field(default=None, max_length=32, index=True)  # e.g. "CWE-89"
    title: str = Field(max_length=300)
    description: str = Field(default="", sa_type=sa.Text)
    remediation: str | None = Field(default=None, sa_type=sa.Text)

    file_path: str = Field(max_length=1024)
    start_line: int = Field(default=1)
    end_line: int = Field(default=1)
    symbol_node_id: str | None = Field(default=None, max_length=1024)

    confidence: float = Field(default=0.5)
    verifier_reasoning: str | None = Field(default=None, sa_type=sa.Text)
    # [{"file": ..., "line": ..., "symbol": ..., "role": "source|propagator|sink", "snippet": ...}]
    taint_flow: list[dict[str, Any]] = Field(default_factory=list, sa_type=_json())
    counted_in_score: bool = Field(default=False)

    created_at: datetime = Field(default_factory=utcnow, sa_type=_tz(), nullable=False)


# --------------------------------------------------------------------------------------
# Persisted call graph
# --------------------------------------------------------------------------------------


class CodeSymbol(SQLModel, table=True):
    """A node of the whole-project symbol graph (see `ast_engine.SymbolInfo`)."""

    __tablename__ = "code_symbols"
    __table_args__ = (
        sa.UniqueConstraint("repository_id", "node_id", name="uq_symbol_repo_node"),
        sa.Index("ix_symbol_repo_file", "repository_id", "file_path"),
    )

    id: int | None = Field(default=None, primary_key=True)
    repository_id: int = Field(foreign_key="repositories.id", index=True, ondelete="CASCADE")

    node_id: str = Field(max_length=1024)  # "pkg.module:Class.method"
    module: str = Field(max_length=512)
    qualname: str = Field(max_length=512)
    symbol_name: str = Field(max_length=255)
    kind: SymbolKind = Field(sa_type=_enum(SymbolKind))
    file_path: str = Field(max_length=1024)
    lineno: int
    end_lineno: int

    docstring: str | None = Field(default=None, sa_type=sa.Text)
    has_type_hints: bool = Field(default=False)
    type_hint_coverage: float = Field(default=0.0)
    cyclomatic_complexity: int = Field(default=1)
    max_nesting: int = Field(default=0)
    source_code: str = Field(default="", sa_type=sa.Text)

    is_entry_point: bool = Field(default=False, index=True)
    route_path: str | None = Field(default=None, max_length=1024)
    http_methods: list[str] = Field(default_factory=list, sa_type=_json())
    sinks: list[dict[str, Any]] = Field(default_factory=list, sa_type=_json())
    sources: list[str] = Field(default_factory=list, sa_type=_json())

    commit_sha: str | None = Field(default=None, max_length=40)
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=_tz(),
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class CodeEdge(SQLModel, table=True):
    """A directed edge (caller -> callee, importer -> imported, subclass -> base)."""

    __tablename__ = "code_edges"
    __table_args__ = (
        sa.UniqueConstraint("repository_id", "source", "target", "kind", name="uq_edge"),
        sa.Index("ix_edge_repo_source", "repository_id", "source"),
        sa.Index("ix_edge_repo_target", "repository_id", "target"),
    )

    id: int | None = Field(default=None, primary_key=True)
    repository_id: int = Field(foreign_key="repositories.id", index=True, ondelete="CASCADE")
    source: str = Field(max_length=1024)
    target: str = Field(max_length=1024)
    kind: EdgeKind = Field(sa_type=_enum(EdgeKind))
    file_path: str = Field(max_length=1024)
    lineno: int = Field(default=0)
    confidence: float = Field(default=1.0)


# --------------------------------------------------------------------------------------
# Time-series (Timescale hypertable)
# --------------------------------------------------------------------------------------


class ScoreSnapshot(SQLModel, table=True):
    """Developer score after each push. Converted to a hypertable on `recorded_at`.

    Timescale requires the partitioning column in every unique index, hence the
    composite primary key (id, recorded_at). Nothing references this table by FK.
    """

    __tablename__ = "score_snapshots"
    __table_args__ = (sa.Index("ix_snapshot_dev_time", "developer_id", "recorded_at"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    recorded_at: datetime = Field(
        default_factory=utcnow, sa_type=_tz(), primary_key=True, nullable=False
    )
    team_id: int = Field(foreign_key="teams.id", index=True, ondelete="CASCADE")
    developer_id: int = Field(foreign_key="developers.id", ondelete="CASCADE")
    push_event_id: int | None = Field(
        default=None, foreign_key="push_events.id", ondelete="SET NULL"
    )

    security_score: int
    craft_score: int
    composite_score: int
    total_pushes: int
    faulty_pushes: int
    points_delta: int = Field(default=0)
    # this push had a verified vulnerability (feeds the team_daily_scores continuous aggregate)
    is_faulty: bool = Field(default=False)
