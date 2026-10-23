"""Shared pytest fixtures for the PhishGuard test-suite.

The fixtures isolate the tests from the developer's real database and from the
rate limiter, so that a test run is deterministic and never touches
``phishguard.db`` in the working directory.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest

# The repository root holds the ``backend``, ``ml`` and ``phishguard`` packages.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from backend.app.core.config import settings  # noqa: E402
from backend.app.database.base import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.services.classifier import model_service  # noqa: E402
import backend.app.models.scan  # noqa: E402,F401  (registers the ORM tables)


#: A well behaved address that the trained model scores as safe.
SAFE_URL = "https://www.google.com/search?q=test"

#: An address with the classic phishing markers the model was trained on.
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"


@pytest.fixture(scope="session", autouse=True)
def loaded_model() -> None:
    """Load the trained artifact once for the whole session."""
    assert model_service.load(force=True), (
        "The trained model artifact could not be loaded: "
        f"{model_service.load_error!r}. Run `python -m ml.src.train` first."
    )


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    """An isolated in-memory SQLite engine with the full schema."""
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    yield test_engine
    test_engine.dispose()


@pytest.fixture(autouse=True)
def clean_database(engine: Engine) -> Iterator[None]:
    """Empty every table before each test so the tests stay independent."""
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    yield


@pytest.fixture(autouse=True)
def neutral_rate_limit() -> Iterator[None]:
    """Disable the rate limiter by default; a dedicated test re-enables it."""
    from backend.app import main as main_module

    previous = settings.rate_limit_enabled
    previous_limit = settings.rate_limit_per_minute
    settings.rate_limit_enabled = False
    main_module._RATE_STORE.clear()
    yield
    settings.rate_limit_enabled = previous
    settings.rate_limit_per_minute = previous_limit
    main_module._RATE_STORE.clear()


@pytest.fixture()
def session_factory(engine: Engine) -> sessionmaker:
    """A session factory bound to the isolated test database."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def db_session(session_factory: sessionmaker) -> Iterator[Session]:
    """A database session for direct service-level assertions."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(session_factory: sessionmaker) -> Iterator[TestClient]:
    """A ``TestClient`` wired to the isolated database.

    The application lifespan is intentionally *not* executed: it would create
    tables in the developer's real database file.  The model is loaded by the
    ``loaded_model`` fixture instead.
    """
    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app, raise_server_exceptions=False)
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()
