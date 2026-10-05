"""Unit tests for Phase 2 cryptographic core (Argon2id, TOTP, CSPRNG tokens)."""

import pyotp

from secure_auth.core.hasher import Argon2PasswordHasher
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


def test_argon2id_hashing_and_verification() -> None:
    """Verifies Argon2id hash formatting, validation, and rejection of bad input."""
    # Use lightweight parameters for test speed
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    pwd = "Synthetic#MasterKey#2026!"

    hashed = hasher.hash_password(pwd)
    assert hashed.startswith("$argon2id$v=19$")

    # Correct verification
    assert hasher.verify_password(hashed, pwd) is True

    # Bad password verification fails cleanly
    assert hasher.verify_password(hashed, "WrongPassword#123") is False

    # Dummy verification always returns False
    assert hasher.verify_dummy(pwd) is False


def test_constant_time_comparison() -> None:
    """Verifies string and bytes constant time comparison."""
    assert constant_time_compare("secret_string_123", "secret_string_123") is True
    assert constant_time_compare("secret_string_123", "secret_string_124") is False

    assert constant_time_compare_bytes(b"data_chunk_a", b"data_chunk_a") is True
    assert constant_time_compare_bytes(b"data_chunk_a", b"data_chunk_b") is False


def test_csprng_tokens_and_hashing() -> None:
    """Verifies session tokens entropy and SHA-256 digest properties."""
    token1 = generate_session_token()
    token2 = generate_session_token()
    assert token1 != token2
    assert len(token1) >= 40

    hashed1 = hash_token(token1)
    assert len(hashed1) == 64  # SHA-256 hex length
    assert hashed1 == hash_token(token1)  # Deterministic

    mfa_challenge = generate_mfa_challenge_token()
    assert len(mfa_challenge) >= 20


def test_totp_mfa_lifecycle() -> None:
    """Verifies RFC 6238 TOTP secret generation, URI, and code verification."""
    secret = generate_totp_secret()
    assert len(secret) == 32

    from urllib.parse import unquote

    uri = generate_provisioning_uri("alice@example.com", secret)
    assert uri.startswith("otpauth://totp/")
    assert "alice@example.com" in unquote(uri)

    # Generate current valid code using pyotp
    current_code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, current_code) is True

    # Bad code fails
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "notdigits") is False


def test_backup_recovery_codes_generation_and_verification() -> None:
    """Verifies generation, formatting, and single-use validation of recovery codes."""
    plain_codes, hashed_codes = generate_backup_recovery_codes(count=5)
    assert len(plain_codes) == 5
    assert len(hashed_codes) == 5

    # Check format XXXX-XXXX-XXXX
    for code in plain_codes:
        parts = code.split("-")
        assert len(parts) == 3
        assert all(len(p) == 4 for p in parts)

    # Verify first code matches
    first_plain = plain_codes[0]
    is_valid, matched_hash = verify_recovery_code(first_plain, hashed_codes)
    assert is_valid is True
    assert matched_hash == hashed_codes[0]

    # Non-existent code fails
    is_valid_bad, matched_bad = verify_recovery_code("ZZZZ-YYYY-XXXX", hashed_codes)
    assert is_valid_bad is False
    assert matched_bad is None
