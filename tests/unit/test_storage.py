"""Unit tests for Phase 3 storage repositories and database models."""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, create_engine

from secure_auth.core.tokens import generate_session_token, hash_token
from secure_auth.storage.database import init_db
from secure_auth.storage.repository import (
    AuditRepository,
    RecoveryCodeRepository,
    SessionRepository,
    UserRepository,
)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Create a fresh in-memory SQLite database session for each test."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as session:
        yield session


def test_user_repository_create_and_lookup(db_session: Session) -> None:
    """Test user creation and case-insensitive retrieval."""
    user_repo = UserRepository(db_session)
    user = user_repo.create("Alice", "ALICE@Example.com", "argon2id_hash_placeholder")

    assert user.id is not None
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.failed_login_attempts == 0

    # Lookup by username case-insensitively
    found = user_repo.get_by_username("ALICE")
    assert found is not None
    assert found.id == user.id

    # Lookup by email case-insensitively
    found_email = user_repo.get_by_email("alice@EXAMPLE.COM")
    assert found_email is not None
    assert found_email.id == user.id

    # Lookup by identifier
    assert user_repo.get_by_identifier("alice") is not None
    assert user_repo.get_by_identifier("alice@example.com") is not None
    assert user_repo.get_by_identifier("nonexistent") is None


def test_user_repository_duplicate_username(db_session: Session) -> None:
    """Ensure duplicate username violates uniqueness constraint."""
    user_repo = UserRepository(db_session)
    user_repo.create("bob", "bob1@example.com", "hash1")

    with pytest.raises(IntegrityError):
        user_repo.create("bob", "bob2@example.com", "hash2")


def test_user_repository_duplicate_email(db_session: Session) -> None:
    """Ensure duplicate email violates uniqueness constraint."""
    user_repo = UserRepository(db_session)
    user_repo.create("bob1", "bob@example.com", "hash1")

    with pytest.raises(IntegrityError):
        user_repo.create("bob2", "bob@example.com", "hash2")


def test_user_failed_attempts_and_lockout(db_session: Session) -> None:
    """Test incrementing failed attempts and setting lockout."""
    user_repo = UserRepository(db_session)
    user = user_repo.create("charlie", "charlie@example.com", "hash")

    locked_time = datetime.now(UTC) + timedelta(minutes=15)
    updated = user_repo.increment_failed_attempts(user, locked_until=locked_time)

    assert updated.failed_login_attempts == 1
    assert updated.locked_until == locked_time

    # Reset failed attempts
    cleared = user_repo.reset_failed_attempts(updated)
    assert cleared.failed_login_attempts == 0
    assert cleared.locked_until is None


def test_session_lifecycle(db_session: Session) -> None:
    """Test session creation, retrieval by token hash, and revocation."""
    user_repo = UserRepository(db_session)
    user = user_repo.create("diana", "diana@example.com", "hash")
    assert user.id is not None

    session_repo = SessionRepository(db_session)
    raw_token = generate_session_token()
    token_digest = hash_token(raw_token)
    expires = datetime.now(UTC) + timedelta(hours=24)

    sess = session_repo.create_session(
        user_id=user.id,
        token_hash=token_digest,
        expires_at=expires,
        ip_address="192.168.1.50",
        user_agent="TestClient/1.0",
        mfa_authenticated=True,
    )
    assert sess.id is not None
    assert sess.is_revoked is False
    assert sess.mfa_authenticated is True

    # Lookup
    found = session_repo.get_by_token_hash(token_digest)
    assert found is not None
    assert found.user_id == user.id

    # Revoke single session
    assert session_repo.revoke_session(token_digest) is True
    revoked = session_repo.get_by_token_hash(token_digest)
    assert revoked is not None
    assert revoked.is_revoked is True

    # Revoking already revoked returns False
    assert session_repo.revoke_session(token_digest) is False


def test_session_revoke_all_and_prune(db_session: Session) -> None:
    """Test bulk session revocation and pruning expired sessions."""
    user_repo = UserRepository(db_session)
    user = user_repo.create("evan", "evan@example.com", "hash")
    assert user.id is not None

    session_repo = SessionRepository(db_session)
    past_expiry = datetime.now(UTC) - timedelta(hours=1)
    future_expiry = datetime.now(UTC) + timedelta(hours=2)

    # One expired session, two active sessions
    session_repo.create_session(user.id, hash_token("token1"), past_expiry)
    session_repo.create_session(user.id, hash_token("token2"), future_expiry)
    session_repo.create_session(user.id, hash_token("token3"), future_expiry)

    # Prune expired
    pruned = session_repo.prune_expired()
    assert pruned == 1

    # Revoke remaining active sessions
    revoked_count = session_repo.revoke_all_user_sessions(user.id)
    assert revoked_count == 2


def test_recovery_codes_single_use(db_session: Session) -> None:
    """Test storage, verification, and single-use consumption of recovery codes."""
    user_repo = UserRepository(db_session)
    user = user_repo.create("fiona", "fiona@example.com", "hash")
    assert user.id is not None

    code_repo = RecoveryCodeRepository(db_session)
    code_hashes = [hash_token(f"code_{i}") for i in range(5)]

    stored = code_repo.store_codes(user.id, code_hashes)
    assert len(stored) == 5
    assert code_repo.get_remaining_count(user.id) == 5

    # Consume one code
    consumed = code_repo.verify_and_consume(user.id, code_hashes[0])
    assert consumed is True
    assert code_repo.get_remaining_count(user.id) == 4

    # Attempting to reuse the same code fails
    assert code_repo.verify_and_consume(user.id, code_hashes[0]) is False
    assert code_repo.get_remaining_count(user.id) == 4

    # Storing new codes overwrites the previous set
    new_hashes = [hash_token("new_code_1"), hash_token("new_code_2")]
    code_repo.store_codes(user.id, new_hashes)
    assert code_repo.get_remaining_count(user.id) == 2


def test_audit_repository_logging(db_session: Session) -> None:
    """Test recording and querying immutable audit events."""
    audit_repo = AuditRepository(db_session)

    audit_repo.log_event(
        event_type="AUTH_LOGIN_SUCCESS",
        user_id=1,
        username="george",
        ip_address="10.0.0.1",
        status="SUCCESS",
        details={"method": "password_mfa"},
    )
    audit_repo.log_event(
        event_type="AUTH_LOGIN_FAILED",
        user_id=None,
        username="unknown_user",
        ip_address="10.0.0.2",
        status="FAILURE",
        details={"reason": "invalid_credentials"},
    )

    events = audit_repo.list_events(limit=10)
    assert len(events) == 2
    assert events[0].event_type == "AUTH_LOGIN_FAILED"  # Most recent first
    assert events[1].event_type == "AUTH_LOGIN_SUCCESS"

    user_events = audit_repo.list_events(user_id=1)
    assert len(user_events) == 1
    assert user_events[0].username == "george"
