"""Database engine and session management with SQLite foreign key enforcement."""

from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, event
from sqlmodel import Session, SQLModel, create_engine

from secure_auth.config.settings import settings


def _set_sqlite_pragma(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enforce foreign key constraints on SQLite connections."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(database_url: str | None = None, echo: bool = False) -> Engine:
    """Create and return a configured SQLAlchemy/SQLModel engine.

    Args:
        database_url: Optional database connection string. Defaults to settings.DATABASE_URL.
        echo: Whether to log SQL statements.

    Returns:
        SQLAlchemy Engine instance.
    """
    url = database_url or settings.DATABASE_URL
    connect_args: dict[str, Any] = {}

    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(url, echo=echo, connect_args=connect_args)

    if url.startswith("sqlite"):
        event.listen(engine, "connect", _set_sqlite_pragma)

    return engine


def init_db(engine: Engine) -> None:
    """Initialize database schema by creating all registered tables.

    Args:
        engine: Database engine to use for schema creation.
    """
    SQLModel.metadata.create_all(engine)


def get_session(engine: Engine) -> Generator[Session, None, None]:
    """Yield a transactional database session with auto-rollback on error.

    Args:
        engine: Engine instance to bind the session to.

    Yields:
        Active SQLModel Session.
    """
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
