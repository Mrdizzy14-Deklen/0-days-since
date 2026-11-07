"""Schema sanity checks: DDL compiles for PostgreSQL and round-trips on SQLite."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from sqlmodel import Session, SQLModel, select

from app.enums import CheckConclusion, FindingCategory, FindingSource, Severity
from app.models import Developer, Finding, PushEvent, Repository, ScoreSnapshot, Team


def test_postgres_ddl_compiles() -> None:
    ddl = {t.name: str(CreateTable(t).compile(dialect=postgresql.dialect()))
           for t in SQLModel.metadata.sorted_tables}
    assert set(ddl) >= {"teams", "repositories", "repo_files", "developers", "push_events",
                        "findings", "code_symbols", "code_edges", "score_snapshots"}
    assert "JSONB" in ddl["push_events"]
    assert "PRIMARY KEY (id, recorded_at)" in ddl["score_snapshots"]  # hypertable-compatible
    assert "BIGINT" in ddl["teams"]  # GitHub installation ids exceed int32


def test_round_trip_sqlite() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        team = Team(name="HackUTD", slug="hackutd", github_installation_id=12_345_678_901)
        s.add(team)
        s.commit()
        repo = Repository(team_id=team.id, github_repo_id=987654321012, owner="acme",
                          name="api", full_name="acme/api")
        dev = Developer(team_id=team.id, github_login="octocat", cwe_counts={"CWE-89": 2})
        s.add_all([repo, dev])
        s.commit()
        push = PushEvent(team_id=team.id, repository_id=repo.id, developer_id=dev.id,
                         after_sha="a" * 40, conclusion=CheckConclusion.FAILURE,
                         blast_radius={"seeds": ["app.db:Database.fetch_user"]})
        s.add(push)
        s.commit()
        s.add(Finding(push_event_id=push.id, repository_id=repo.id,
                      category=FindingCategory.SECURITY, source=FindingSource.STATIC,
                      severity=Severity.HIGH, rule_id="PY-SEC-003", cwe="CWE-89",
                      title="SQLi", file_path="app/db.py", start_line=12, end_line=12))
        s.add(ScoreSnapshot(team_id=team.id, developer_id=dev.id, push_event_id=push.id,
                            security_score=455, craft_score=210, composite_score=665,
                            total_pushes=2, faulty_pushes=1, points_delta=-245))
        s.commit()

        loaded = s.exec(select(PushEvent)).one()
        assert loaded.conclusion is CheckConclusion.FAILURE
        assert loaded.blast_radius["seeds"] == ["app.db:Database.fetch_user"]
        assert s.exec(select(Finding)).one().severity is Severity.HIGH
        assert dev.composite_score == 1000 and dev.security_score == 700
