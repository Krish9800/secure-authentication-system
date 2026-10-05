"""Cryptographic core package exports."""

from secure_auth.core.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AuthError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    InvalidTokenError,
    MFARequiredError,
    SessionExpiredError,
    UserAlreadyExistsError,
)
from secure_auth.core.hasher import Argon2PasswordHasher, password_hasher
from secure_auth.core.mfa import (
    generate_backup_recovery_codes,
    generate_provisioning_uri,
    generate_totp_secret,
    verify_recovery_code,
    verify_totp_code,
)
from secure_auth.core.timing import constant_time_compare, constant_time_compare_bytes
from secure_auth.core.tokens import (
    generate_mfa_challenge_token,
    generate_session_token,
    hash_token,
)

__all__ = [
    "Argon2PasswordHasher",
    "password_hasher",
    "constant_time_compare",
    "constant_time_compare_bytes",
    "generate_session_token",
    "hash_token",
    "generate_mfa_challenge_token",
    "generate_totp_secret",
    "generate_provisioning_uri",
    "verify_totp_code",
    "generate_backup_recovery_codes",
    "verify_recovery_code",
    "AuthError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "AccountInactiveError",
    "UserAlreadyExistsError",
    "InvalidTokenError",
    "SessionExpiredError",
    "MFARequiredError",
    "InvalidMFACodeError",
]
