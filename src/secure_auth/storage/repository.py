"""Repository layer providing clean transactional data access abstractions."""

import json
from datetime import UTC, datetime
from typing import Any

from sqlmodel import Session as DbSession
from sqlmodel import col, select

from secure_auth.models.audit import SecurityAuditEvent
from secure_auth.models.recovery_code import BackupRecoveryCode
from secure_auth.models.session import Session
from secure_auth.models.user import User


class UserRepository:
    """Repository handling User entity persistence and lifecycle operations."""

    def __init__(self, session: DbSession) -> None:
        self.session = session

    def get_by_id(self, user_id: int) -> User | None:
        """Fetch user by primary key ID."""
        return self.session.get(User, user_id)

    def get_by_username(self, username: str) -> User | None:
        """Fetch user by unique lowercase username."""
        statement = select(User).where(col(User.username) == username.strip().lower())
        return self.session.exec(statement).first()

    def get_by_email(self, email: str) -> User | None:
        """Fetch user by unique lowercase email address."""
        statement = select(User).where(col(User.email) == email.strip().lower())
        return self.session.exec(statement).first()

    def get_by_identifier(self, identifier: str) -> User | None:
        """Fetch user by either username or email address."""
        normalized = identifier.strip().lower()
        statement = select(User).where(
            (col(User.username) == normalized) | (col(User.email) == normalized)
        )
        return self.session.exec(statement).first()

    def create(self, username: str, email: str, password_hash: str) -> User:
        """Persist a new user account with normalized identity fields."""
        now = datetime.now(UTC)
        user = User(
            username=username.strip().lower(),
            email=email.strip().lower(),
            password_hash=password_hash,
            created_at=now,
            updated_at=now,
        )
        self.session.add(user)
        self.session.flush()
        self.session.refresh(user)
        return user

    def update(self, user: User) -> User:
        """Save updates to an existing user."""
        user.updated_at = datetime.now(UTC)
        merged = self.session.merge(user)
        self.session.flush()
        self.session.refresh(merged)
        return merged

    def increment_failed_attempts(self, user: User, locked_until: datetime | None = None) -> User:
        """Increment failed login attempts counter and optionally set lockout."""
        merged = self.session.merge(user)
        merged.failed_login_attempts += 1
        if locked_until is not None:
            merged.locked_until = locked_until
        merged.updated_at = datetime.now(UTC)
        self.session.flush()
        self.session.refresh(merged)
        return merged

    def reset_failed_attempts(self, user: User) -> User:
        """Clear failed login attempts counter and any active lockout."""
        merged = self.session.merge(user)
        merged.failed_login_attempts = 0
        merged.locked_until = None
        merged.updated_at = datetime.now(UTC)
        self.session.flush()
        self.session.refresh(merged)
        return merged


class SessionRepository:
    """Repository managing user session persistence and token hash lookups."""

    def __init__(self, session: DbSession) -> None:
        self.session = session

    def create_session(
        self,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
        mfa_authenticated: bool = False,
    ) -> Session:
        """Create and persist a new session record."""
        session_record = Session(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False,
            mfa_authenticated=mfa_authenticated,
        )
        self.session.add(session_record)
        self.session.flush()
        self.session.refresh(session_record)
        return session_record

    def get_by_token_hash(self, token_hash: str) -> Session | None:
        """Retrieve session record by token digest."""
        statement = select(Session).where(col(Session.token_hash) == token_hash)
        return self.session.exec(statement).first()

    def revoke_session(self, token_hash: str) -> bool:
        """Mark a specific session as revoked."""
        record = self.get_by_token_hash(token_hash)
        if record and not record.is_revoked:
            record.is_revoked = True
            self.session.add(record)
            self.session.flush()
            return True
        return False

    def revoke_all_user_sessions(self, user_id: int) -> int:
        """Revoke all active sessions for a user."""
        statement = select(Session).where(
            (col(Session.user_id) == user_id) & (col(Session.is_revoked) == False)  # noqa: E712
        )
        records = self.session.exec(statement).all()
        count = len(records)
        for record in records:
            record.is_revoked = True
            self.session.add(record)
        self.session.flush()
        return count

    def prune_expired(self) -> int:
        """Delete sessions expired past their expiry timestamp."""
        now = datetime.now(UTC)
        statement = select(Session).where(col(Session.expires_at) < now)
        records = self.session.exec(statement).all()
        count = len(records)
        for record in records:
            self.session.delete(record)
        self.session.flush()
        return count


class RecoveryCodeRepository:
    """Repository handling single-use backup recovery codes."""

    def __init__(self, session: DbSession) -> None:
        self.session = session

    def store_codes(self, user_id: int, code_hashes: list[str]) -> list[BackupRecoveryCode]:
        """Invalidate old recovery codes and store new batch."""
        statement = select(BackupRecoveryCode).where(col(BackupRecoveryCode.user_id) == user_id)
        existing = self.session.exec(statement).all()
        for item in existing:
            self.session.delete(item)
        self.session.flush()

        new_codes: list[BackupRecoveryCode] = []
        for ch in code_hashes:
            code = BackupRecoveryCode(user_id=user_id, code_hash=ch)
            self.session.add(code)
            new_codes.append(code)

        self.session.flush()
        return new_codes

    def verify_and_consume(self, user_id: int, code_hash: str) -> bool:
        """Atomically verify and consume an unused recovery code."""
        statement = select(BackupRecoveryCode).where(
            (col(BackupRecoveryCode.user_id) == user_id)
            & (col(BackupRecoveryCode.code_hash) == code_hash)
            & (col(BackupRecoveryCode.is_used) == False)  # noqa: E712
        )
        record = self.session.exec(statement).first()
        if record:
            record.is_used = True
            record.used_at = datetime.now(UTC)
            self.session.add(record)
            self.session.flush()
            return True
        return False

    def get_remaining_count(self, user_id: int) -> int:
        """Return the number of unused backup codes remaining."""
        statement = select(BackupRecoveryCode).where(
            (col(BackupRecoveryCode.user_id) == user_id)
            & (col(BackupRecoveryCode.is_used) == False)  # noqa: E712
        )
        return len(self.session.exec(statement).all())


class AuditRepository:
    """Repository logging immutable security audit events."""

    def __init__(self, session: DbSession) -> None:
        self.session = session

    def log_event(
        self,
        event_type: str,
        user_id: int | None = None,
        username: str | None = None,
        ip_address: str | None = None,
        status: str = "SUCCESS",
        details: dict[str, Any] | None = None,
    ) -> SecurityAuditEvent:
        """Record an immutable security audit event."""
        details_json = json.dumps(details) if details else None
        event = SecurityAuditEvent(
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            status=status,
            details_json=details_json,
        )
        self.session.add(event)
        self.session.flush()
        self.session.refresh(event)
        return event

    def list_events(self, limit: int = 100, user_id: int | None = None) -> list[SecurityAuditEvent]:
        """Fetch audit log events ordered by timestamp descending."""
        statement = select(SecurityAuditEvent)
        if user_id is not None:
            statement = statement.where(col(SecurityAuditEvent.user_id) == user_id)
        statement = statement.order_by(col(SecurityAuditEvent.timestamp).desc()).limit(limit)
        return list(self.session.exec(statement).all())
