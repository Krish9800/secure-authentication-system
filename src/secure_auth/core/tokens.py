"""Cryptographically secure pseudorandom token generation and hashing."""

import hashlib
import secrets

from secure_auth.config.settings import settings


def generate_session_token(nbytes: int | None = None) -> str:
    """Generate a high-entropy CSPRNG session token.

    Args:
        nbytes: Byte length of random entropy (default from settings).

    Returns:
        URL-safe high-entropy base64 string.
    """
    byte_count = nbytes or settings.SESSION_TOKEN_BYTES
    return secrets.token_urlsafe(byte_count)


def hash_token(raw_token: str) -> str:
    """Compute one-way SHA-256 digest of token for storage at rest.

    Storing hashed session tokens prevents token reuse or session hijacking
    in the event of database backup or read replicas leakage.

    Args:
        raw_token: Plaintext token string.

    Returns:
        64-character hexadecimal SHA-256 hash string.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_mfa_challenge_token() -> str:
    """Generate a temporary 160-bit challenge token for MFA step-up flow."""
    return secrets.token_urlsafe(20)
