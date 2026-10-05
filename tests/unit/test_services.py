"""Unit tests for security services: AuthService, LockoutService, MFAService, AuditService."""

from collections.abc import Generator

import pyotp
import pytest
from sqlmodel import Session, create_engine

from secure_auth.config.settings import settings
from secure_auth.core.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    InvalidTokenError,
    UserAlreadyExistsError,
)
from secure_auth.core.hasher import Argon2PasswordHasher
from secure_auth.services.audit_service import AuditService
from secure_auth.services.auth_service import AuthService
from secure_auth.services.mfa_service import MFAService
from secure_auth.storage.database import init_db
from secure_auth.storage.repository import UserRepository


@pytest.fixture
def fast_hasher() -> Argon2PasswordHasher:
    """Fast Argon2id hasher for test suite execution."""
    return Argon2PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """In-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as session:
        yield session


def test_registration_success_and_normalization(
    db_session: Session, fast_hasher: Argon2PasswordHasher
) -> None:
    """Test user registration with field normalization and password hashing."""
    auth = AuthService(db_session, hasher=fast_hasher)
    user = auth.register("AliceSmith", "Alice@Example.COM", "P@ssword1234!")

    assert user.id is not None
    assert user.username == "alicesmith"
    assert user.email == "alice@example.com"
    assert user.password_hash.startswith("$argon2id$")
    assert user.is_active is True
    assert user.mfa_enabled is False


def test_registration_validation_and_duplicate(
    db_session: Session, fast_hasher: Argon2PasswordHasher
) -> None:
    """Ensure invalid parameters and duplicate identities are rejected."""
    auth = AuthService(db_session, hasher=fast_hasher)

    # Invalid username length
    with pytest.raises(ValueError, match="at least 3 characters"):
        auth.register("a", "test@example.com", "valid_password")

    # Invalid email
    with pytest.raises(ValueError, match="Invalid email format"):
        auth.register("validuser", "notanemail", "valid_password")

    # Short password
    with pytest.raises(ValueError, match="at least 8 characters"):
        auth.register("validuser", "test@example.com", "short")

    # Duplicates
    auth.register("existing", "existing@example.com", "valid_password_123")
    with pytest.raises(UserAlreadyExistsError):
        auth.register("existing", "other@example.com", "valid_password_123")

    with pytest.raises(UserAlreadyExistsError):
        auth.register("other", "existing@example.com", "valid_password_123")


def test_authenticate_success_and_invalid(
    db_session: Session, fast_hasher: Argon2PasswordHasher
) -> None:
    """Test primary login success and credential failure handling."""
    auth = AuthService(db_session, hasher=fast_hasher)
    auth.register("bob", "bob@example.com", "CorrectPassword123")

    # Successful login
    user, raw_token, mfa_required = auth.authenticate("bob", "CorrectPassword123")
    assert user.username == "bob"
    assert len(raw_token) >= 32
    assert mfa_required is False

    # Successful login by email
    user_email, _, _ = auth.authenticate("bob@example.com", "CorrectPassword123")
    assert user_email.id == user.id

    # Wrong password raises InvalidCredentialsError
    with pytest.raises(InvalidCredentialsError):
        auth.authenticate("bob", "WrongPassword!")

    # Non-existent user raises generic InvalidCredentialsError (timing-defended)
    with pytest.raises(InvalidCredentialsError):
        auth.authenticate("ghost_user", "AnyPassword123")


def test_lockout_trigger_and_recovery(
    db_session: Session, fast_hasher: Argon2PasswordHasher
) -> None:
    """Test brute-force lockout after threshold failures and unlock recovery."""
    auth = AuthService(db_session, hasher=fast_hasher)
    auth.register("target", "target@example.com", "RealPassword123")

    # Fail MAX_FAILED_LOGIN_ATTEMPTS - 1 times (4 times)
    for _ in range(settings.MAX_FAILED_LOGIN_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentialsError):
            auth.authenticate("target", "WrongPass")

    # 5th failure triggers AccountLockedError
    with pytest.raises(AccountLockedError) as exc_info:
        auth.authenticate("target", "WrongPass")
    assert exc_info.value.remaining_seconds > 0

    # Subsequent attempt with CORRECT password is still locked out
    with pytest.raises(AccountLockedError):
        auth.authenticate("target", "RealPassword123")

    # Admin unlock
    user_repo = UserRepository(db_session)
    user = user_repo.get_by_username("target")
    assert user is not None
    auth.lockout_service.unlock_user(user)

    # Now login succeeds and failure counter resets
    user_unlocked, token, mfa_req = auth.authenticate("target", "RealPassword123")
    assert user_unlocked.failed_login_attempts == 0
    assert mfa_req is False


def test_mfa_full_lifecycle(db_session: Session, fast_hasher: Argon2PasswordHasher) -> None:
    """Test MFA setup, confirmation, step-up login with TOTP, and backup codes."""
    auth = AuthService(db_session, hasher=fast_hasher)
    mfa = MFAService(db_session)

    user = auth.register("carol", "carol@example.com", "StrongPassword123!")

    # 1. Setup MFA
    secret, uri, backup_codes = mfa.setup_mfa(user)
    assert secret and len(secret) == 32
    assert "otpauth://totp/" in uri
    assert len(backup_codes) == settings.BACKUP_RECOVERY_CODES_COUNT

    # Confirm with invalid TOTP code fails
    with pytest.raises(InvalidMFACodeError):
        mfa.confirm_mfa(user, "000000")

    # Confirm with valid TOTP code
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    assert mfa.confirm_mfa(user, valid_code) is True

    # Refresh user
    user_repo = UserRepository(db_session)
    refreshed_user = user_repo.get_by_id(user.id)  # type: ignore[arg-type]
    assert refreshed_user is not None
    assert refreshed_user.mfa_enabled is True

    # 2. Authenticate: Should require MFA challenge
    u, mfa_token, mfa_required = auth.authenticate("carol", "StrongPassword123!")
    assert mfa_required is True

    # Attempting to use mfa_token as session token should fail
    with pytest.raises(InvalidTokenError):
        auth.validate_session(mfa_token)

    # 3. Complete MFA login with TOTP
    active_totp_code = pyotp.TOTP(secret).now()
    user_mfa, valid_session_token = auth.complete_mfa_login(mfa_token, active_totp_code)
    assert user_mfa.id == user.id

    # Now session validation succeeds
    valid_user, valid_session = auth.validate_session(valid_session_token)
    assert valid_user.id == user.id
    assert valid_session.mfa_authenticated is True

    # 4. Step-up login with single-use backup recovery code
    _, mfa_token2, req2 = auth.authenticate("carol", "StrongPassword123!")
    assert req2 is True

    used_code = backup_codes[0]
    auth.complete_mfa_login(mfa_token2, used_code)

    # Reusing the same backup code must fail
    _, mfa_token3, _ = auth.authenticate("carol", "StrongPassword123!")
    with pytest.raises(InvalidMFACodeError):
        auth.complete_mfa_login(mfa_token3, used_code)

    # 5. Disable MFA
    current_code = pyotp.TOTP(secret).now()
    assert mfa.disable_mfa(refreshed_user, current_code) is True
    assert refreshed_user.mfa_enabled is False


def test_session_validation_and_logout(
    db_session: Session, fast_hasher: Argon2PasswordHasher
) -> None:
    """Test session validation, revocation, and bulk logout."""
    auth = AuthService(db_session, hasher=fast_hasher)
    user = auth.register("david", "david@example.com", "Password12345!")

    _, token1, _ = auth.authenticate("david", "Password12345!")
    _, token2, _ = auth.authenticate("david", "Password12345!")

    # Validate token1
    valid_u, sess1 = auth.validate_session(token1)
    assert valid_u.id == user.id
    assert sess1.is_revoked is False

    # Logout token1
    assert auth.logout(token1) is True
    with pytest.raises(InvalidTokenError):
        auth.validate_session(token1)

    # token2 is still valid
    assert auth.validate_session(token2) is not None

    # Bulk logout
    assert user.id is not None
    auth.logout_all(user.id)
    with pytest.raises(InvalidTokenError):
        auth.validate_session(token2)


def test_audit_scrubbing(db_session: Session) -> None:
    """Ensure sensitive credentials are redacted before persisting audit logs."""
    audit = AuditService(db_session)
    event = audit.log(
        event_type="TEST_EVENT",
        user_id=1,
        username="audit_test",
        details={
            "password": "SuperSecretPassword!",
            "token": "raw_token_value",
            "recovery_code": "code123",
            "safe_field": "public_info",
        },
    )

    assert event.details_json is not None
    assert "SuperSecretPassword!" not in event.details_json
    assert "raw_token_value" not in event.details_json
    assert "code123" not in event.details_json
    assert "[REDACTED]" in event.details_json
    assert "public_info" in event.details_json
