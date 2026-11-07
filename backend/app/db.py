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
            connect_args["ssl"] = ssl.create_default_context()
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


async def dispose_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
