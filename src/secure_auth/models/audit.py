"""Audit logging domain model for security event tracing."""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class SecurityAuditEvent(SQLModel, table=True):
    """Immutable security audit log entry.

    Attributes:
        id: Primary key surrogate identifier.
        timestamp: Event occurrence timestamp in UTC.
        event_type: Standardized security event classification (e.g. AUTH_LOGIN_SUCCESS).
        user_id: Optional ID of the user involved.
        username: Optional username involved (useful if user does not exist).
        ip_address: Client IP address initiating the event.
        status: Event outcome status (SUCCESS, FAILURE, WARNING, CRITICAL).
        details_json: Sanitized JSON payload with non-sensitive contextual details.
    """

    __tablename__ = "security_audit_events"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )
    event_type: str = Field(index=True, nullable=False)
    user_id: int | None = Field(default=None, index=True, nullable=True)
    username: str | None = Field(default=None, index=True, nullable=True)
    ip_address: str | None = Field(default=None, nullable=True)
    status: str = Field(default="SUCCESS", nullable=False)
    details_json: str | None = Field(default=None, nullable=True)
