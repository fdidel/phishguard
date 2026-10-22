"""SQLAlchemy engine, session factory and dependency provider.

The database URL is read from the ``DATABASE_URL`` environment variable
(defaulting to a local SQLite file).  ``init_db()`` creates all tables defined
in :mod:`backend.app.models` so the service can start without running Alembic
migrations first.  For production deployments prefer Alembic migrations (see
``backend/alembic/``).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Declarative base class for every ORM model."""


def _build_engine() -> Engine:
    """Create the SQLAlchemy engine from the configured database URL."""
    url = settings.database_url

    if url.startswith("sqlite"):
        # Make sure the target directory exists for file-backed databases.
        path = settings.database_path
        if path:
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)

        if ":memory:" in url:
            # An in-memory SQLite database must share one connection, otherwise
            # every session would see an empty database.
            engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
            )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
            """Enable foreign-key enforcement on SQLite."""
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

        return engine

    return create_engine(url, pool_pre_ping=True)


#: Application-wide engine.
engine = _build_engine()

#: Session factory bound to :data:`engine`.
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped database session.

    The session is always closed, even if the request handler raises.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def alembic_manages_schema() -> bool:
    """Return ``True`` when the database was migrated with Alembic.

    Alembic keeps its bookkeeping in the ``alembic_version`` table.  The table
    alone is not enough evidence: read-only Alembic commands such as
    ``alembic current`` create an *empty* version table, and a database in
    that state still has no application tables.  The schema is therefore only
    considered Alembic-managed when the table exists **and** contains at least
    one stamped revision.
    """
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(engine)
        if "alembic_version" not in inspector.get_table_names():
            return False
        with engine.connect() as connection:
            rows = connection.execute(text("SELECT version_num FROM alembic_version")).fetchall()
        return bool(rows)
    except Exception as exc:  # pragma: no cover - inspection must never crash start-up
        logger.warning("Could not inspect the database for Alembic metadata: %s", exc)
        return False


def init_db() -> None:
    """Create every table registered on :class:`Base`.

    This is the zero-configuration path used by the test-suite and by local
    development.  When the database is already managed by Alembic the call is a
    no-op, so the application can start after ``alembic upgrade head`` without
    any additional step.
    """
    # Importing the models registers them on the declarative metadata.
    import backend.app.models  # noqa: F401

    if alembic_manages_schema():
        logger.info(
            "Database schema is managed by Alembic - skipping create_all (%s)",
            settings.database_url,
        )
        return

    Base.metadata.create_all(bind=engine)
    logger.info("Database initialised at %s", settings.database_url)
