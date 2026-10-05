"""Multi-Factor Authentication (MFA) engine: RFC 6238 TOTP and backup codes."""

import secrets

import pyotp

from secure_auth.config.settings import settings
from secure_auth.core.tokens import hash_token


def generate_totp_secret() -> str:
    """Generate a 160-bit cryptographically secure Base32 TOTP secret.

    Returns:
        32-character Base32 encoded secret key.
    """
    return pyotp.random_base32()


def generate_provisioning_uri(
    username: str,
    secret: str,
    issuer_name: str | None = None,
) -> str:
    """Generate RFC 6238 standard otpauth URI for authenticator app enrollment.

    Args:
        username: User identifier (email or username).
        secret: Base32 TOTP secret key.
        issuer_name: Organization or application name.

    Returns:
        otpauth:// URI string compatible with Google Authenticator, Bitwarden, etc.
    """
    issuer = issuer_name or settings.TOTP_ISSUER_NAME
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str, window: int | None = None) -> bool:
    """Verify a 6-digit TOTP code against the secret with clock-drift tolerance.

    Args:
        secret: Base32 TOTP secret key.
        code: 6-digit user-submitted code.
        window: Number of 30-second time-steps forward and backward to tolerate (default 1).

    Returns:
        True if code is valid within the time window, False otherwise.
    """
    clean_code = code.strip().replace(" ", "")
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False

    tolerance = window if window is not None else settings.TOTP_WINDOW
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(clean_code, valid_window=tolerance))


def generate_backup_recovery_codes(
    count: int | None = None,
) -> tuple[list[str], list[str]]:
    """Generate single-use emergency backup recovery codes.

    Returns:
        Tuple of (formatted_plaintext_codes, hashed_codes_for_storage).
    """
    num_codes = count or settings.BACKUP_RECOVERY_CODES_COUNT
    plaintext_codes: list[str] = []
    hashed_codes: list[str] = []

    for _ in range(num_codes):
        # Generate 12-char random alphanumeric string in 4-char groups (e.g. A1B2-C3D4-E5F6)
        raw = secrets.token_hex(6).upper()
        formatted = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"
        plaintext_codes.append(formatted)

        # Store normalized SHA-256 hash
        normalized = raw.replace("-", "").upper()
        hashed_codes.append(hash_token(normalized))

    return plaintext_codes, hashed_codes


def verify_recovery_code(
    provided_code: str,
    stored_hashes: list[str],
) -> tuple[bool, str | None]:
    """Verify emergency recovery code against stored one-way hashes.

    Args:
        provided_code: User-submitted recovery code.
        stored_hashes: List of unused recovery code hashes.

    Returns:
        Tuple of (is_valid, matching_hash_to_consume).
    """
    normalized = provided_code.strip().replace("-", "").replace(" ", "").upper()
    submitted_hash = hash_token(normalized)

    for h in stored_hashes:
        if secrets.compare_digest(submitted_hash, h):
            return True, h

    return False, None
