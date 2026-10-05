"""Backup recovery code domain model for multi-factor recovery."""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class BackupRecoveryCode(SQLModel, table=True):
    """Emergency single-use backup recovery code for MFA.

    Attributes:
        id: Primary key surrogate identifier.
        user_id: Foreign key referencing the owning user.
        code_hash: SHA-256 digest of the plaintext recovery code.
        is_used: True once the single-use code has been consumed.
        used_at: Timestamp of when the code was redeemed in UTC.
        created_at: Code generation timestamp in UTC.
    """

    __tablename__ = "backup_recovery_codes"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True, nullable=False)
    code_hash: str = Field(unique=True, index=True, nullable=False)
    is_used: bool = Field(default=False, nullable=False)
    used_at: datetime | None = Field(default=None, nullable=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )
