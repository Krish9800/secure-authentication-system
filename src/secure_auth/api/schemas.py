"""Pydantic request and response schemas for REST API endpoints."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    """Payload for user account registration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    """Response returned upon successful registration."""

    uuid: str
    username: str
    email: str
    message: str = "User account successfully registered."


class LoginRequest(BaseModel):
    """Payload for primary authentication."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username_or_email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    """Response returned upon primary authentication attempt."""

    status: str  # "authenticated" or "mfa_required"
    token: str
    mfa_required: bool
    message: str


class MFAVerifyRequest(BaseModel):
    """Payload for secondary multi-factor verification."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfa_token: str
    code: str = Field(min_length=6, max_length=20)


class MFASetupResponse(BaseModel):
    """Response containing provisioning details for authenticator app enrollment."""

    secret: str
    provisioning_uri: str
    backup_recovery_codes: list[str]
    message: str = "Scan QR URI or enter secret in authenticator app, then confirm with a code."


class MFAConfirmRequest(BaseModel):
    """Payload for confirming newly enrolled authenticator secret."""

    model_config = ConfigDict(str_strip_whitespace=True)

    code: str = Field(min_length=6, max_length=10)


class MFADisableRequest(BaseModel):
    """Payload for safely disabling MFA."""

    model_config = ConfigDict(str_strip_whitespace=True)

    code: str = Field(min_length=6, max_length=20)


class UserProfileResponse(BaseModel):
    """User profile information returned to authenticated clients."""

    uuid: str
    username: str
    email: str
    mfa_enabled: bool
    created_at: datetime


class MessageResponse(BaseModel):
    """Generic status message response."""

    message: str
    detail: str | None = None


class AuditEventResponse(BaseModel):
    """Serialized audit log entry."""

    id: int
    timestamp: datetime
    event_type: str
    status: str
    details: str | None = None
