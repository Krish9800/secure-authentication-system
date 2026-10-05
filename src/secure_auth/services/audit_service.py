"""Structured security audit service with sensitive data redaction."""

from typing import Any

from sqlmodel import Session

from secure_auth.models.audit import SecurityAuditEvent
from secure_auth.storage.repository import AuditRepository


class AuditService:
    """Records tamper-evident security audit logs with strict payload sanitization."""

    # Redaction blacklist for keys containing sensitive cryptographic secrets
    SENSITIVE_KEYS = {
        "password",
        "password_hash",
        "secret",
        "mfa_secret",
        "token",
        "raw_token",
        "code",
        "recovery_code",
        "credentials",
        "authorization",
    }

    def __init__(self, db_session: Session) -> None:
        self.db_session = db_session
        self.audit_repo = AuditRepository(db_session)

    def _sanitize(self, data: dict[str, Any] | None) -> dict[str, Any] | None:
        """Recursively scrub sensitive keys and credentials from audit metadata."""
        if data is None:
            return None

        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            if k.lower() in self.SENSITIVE_KEYS:
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize(v)
            else:
                sanitized[k] = v
        return sanitized

    def log(
        self,
        event_type: str,
        user_id: int | None = None,
        username: str | None = None,
        ip_address: str | None = None,
        status: str = "SUCCESS",
        details: dict[str, Any] | None = None,
    ) -> SecurityAuditEvent:
        """Sanitize metadata and record an immutable audit event.

        Args:
            event_type: Standard classification string (e.g. AUTH_LOGIN_SUCCESS).
            user_id: Optional ID of user.
            username: Optional username.
            ip_address: Originating client IP.
            status: Outcome status (SUCCESS, FAILURE, WARNING, CRITICAL).
            details: Contextual metadata dictionary.

        Returns:
            Created SecurityAuditEvent instance.
        """
        clean_details = self._sanitize(details)
        return self.audit_repo.log_event(
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            status=status,
            details=clean_details,
        )

    def get_user_events(
        self, user_id: int, limit: int = 50
    ) -> list[SecurityAuditEvent]:
        """Fetch audit trail for a specific user."""
        return self.audit_repo.list_events(limit=limit, user_id=user_id)

    def get_recent_events(self, limit: int = 100) -> list[SecurityAuditEvent]:
        """Fetch system-wide recent security audit trail."""
        return self.audit_repo.list_events(limit=limit)
