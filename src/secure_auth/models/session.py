"""Session domain model for active user sessions."""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class Session(SQLModel, table=True):
    """Session entity tracking user sessions and verification state.

    Attributes:
        id: Primary key surrogate identifier.
        user_id: Foreign key referencing the authenticated user.
        token_hash: SHA-256 digest of the raw bearer token (never store raw token).
        created_at: Session establishment timestamp in UTC.
        expires_at: Session expiration timestamp in UTC.
        ip_address: Client IP address observed during session establishment.
        user_agent: Client User-Agent header observed.
        is_revoked: Whether the session was manually or automatically revoked.
        mfa_authenticated: Whether secondary factor authentication was completed.
    """

    __tablename__ = "sessions"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True, nullable=False)
    token_hash: str = Field(unique=True, index=True, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: datetime = Field(nullable=False, index=True)
    ip_address: str | None = Field(default=None, nullable=True)
    user_agent: str | None = Field(default=None, nullable=True)
    is_revoked: bool = Field(default=False, nullable=False)
    mfa_authenticated: bool = Field(default=False, nullable=False)
