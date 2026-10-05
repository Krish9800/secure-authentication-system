"""User domain model for secure authentication."""

import uuid
from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    """User account model storing identity and security state.

    Attributes:
        id: Primary key surrogate identifier.
        uuid: Public UUID identifier.
        username: Normalized unique username.
        email: Normalized unique email address.
        password_hash: Argon2id password hash string.
        is_active: Whether account is active.
        is_verified: Whether email/identity has been verified.
        mfa_enabled: Whether 2FA (TOTP) is enforced.
        mfa_secret: Optional Base32 TOTP secret key.
        failed_login_attempts: Counter for failed authentication attempts.
        locked_until: Timestamp until which account is temporarily locked.
        created_at: Account creation timestamp in UTC.
        updated_at: Account last modified timestamp in UTC.
    """

    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        unique=True,
        index=True,
        nullable=False,
    )
    username: str = Field(unique=True, index=True, nullable=False)
    email: str = Field(unique=True, index=True, nullable=False)
    password_hash: str = Field(nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    is_verified: bool = Field(default=False, nullable=False)
    mfa_enabled: bool = Field(default=False, nullable=False)
    mfa_secret: str | None = Field(default=None, nullable=True)
    failed_login_attempts: int = Field(default=0, nullable=False)
    locked_until: datetime | None = Field(default=None, nullable=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )
