"""Async database engine, session factory and schema bootstrap (incl. TimescaleDB)."""

from __future__ import annotations

import logging
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app import models  # noqa: F401  (registers tables on SQLModel.metadata)
from app.config import get_settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Create (once) and return the async engine."""
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        connect_args: dict = {}
        if settings.database_url.startswith("postgresql+asyncpg") and settings.database_ssl:
            # Tiger Data / Timescale Cloud require TLS.
            connect_args["ssl"] = ssl.create_default_context(
                cafile=settings.database_ssl_root_cert or None)
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.database_echo,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        _session_factory = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional scope for background jobs: commits on success, rolls back on error."""
    async with get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session."""
    async with get_session_factory()() as session:
        yield session


async def init_db() -> None:
    """Create tables and, when available, enable TimescaleDB + the score hypertable."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    if engine.dialect.name != "postgresql" or not get_settings().enable_timescale:
        return

    # Separate transaction: failure here (plain Postgres without the extension) is non-fatal.
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            await conn.execute(
                text(
                    "SELECT create_hypertable('score_snapshots', 'recorded_at', "
                    "if_not_exists => TRUE, migrate_data => TRUE)"
                )
            )
        logger.info("TimescaleDB hypertable 'score_snapshots' is ready")
    except Exception as exc:  # extension not installed / insufficient privileges
        logger.warning("TimescaleDB unavailable, using a plain table for score_snapshots: %s", exc)
        return
    await _ensure_timescale_extras(engine)


DAILY_VIEW = "team_daily_scores"

# Per-team daily roll-up of every scored push, maintained by TimescaleDB. Real-time
# aggregation (materialized_only = false) adds rows newer than the last refresh on the fly.
_TIMESCALE_EXTRAS = [
    # columns added after a table already existed (create_all never alters tables)
    "ALTER TABLE score_snapshots ADD COLUMN IF NOT EXISTS is_faulty boolean NOT NULL DEFAULT false",
    f"""CREATE MATERIALIZED VIEW IF NOT EXISTS {DAILY_VIEW}
        WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
        SELECT time_bucket(INTERVAL '1 day', recorded_at) AS day,
               team_id,
               count(*) AS pushes,
               sum(CASE WHEN is_faulty THEN 1 ELSE 0 END) AS faulty_pushes,
               sum(points_delta) AS net_points,
               avg(composite_score)::double precision AS avg_composite,
               min(composite_score) AS min_composite,
               max(composite_score) AS max_composite
        FROM score_snapshots
        GROUP BY day, team_id
        WITH NO DATA""",
    f"""SELECT add_continuous_aggregate_policy('{DAILY_VIEW}',
        start_offset => INTERVAL '400 days', end_offset => INTERVAL '1 hour',
        schedule_interval => INTERVAL '15 minutes', if_not_exists => TRUE)""",
    # old score history is read rarely: compress it (segment by team for the dashboard queries)
    "ALTER TABLE score_snapshots SET (timescaledb.compress, "
    "timescaledb.compress_segmentby = 'team_id')",
    "SELECT add_compression_policy('score_snapshots', INTERVAL '90 days', if_not_exists => TRUE)",
]


async def _ensure_timescale_extras(engine: AsyncEngine) -> None:
    """Continuous aggregate + policies. Each step is independent and safe to re-run."""
    async with engine.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        for statement in _TIMESCALE_EXTRAS:
            try:
                await conn.execute(text(statement))
            except Exception as exc:  # e.g. compression already enabled with chunks present
                logger.info("TimescaleDB setup step skipped (%s): %s",
                            statement.split()[0:3], str(exc).splitlines()[0])
        logger.info("TimescaleDB continuous aggregate '%s' is ready", DAILY_VIEW)


async def dispose_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
