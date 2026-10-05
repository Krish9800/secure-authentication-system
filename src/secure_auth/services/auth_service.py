"""High-level authentication orchestration service with timing defense."""

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from secure_auth.config.settings import settings
from secure_auth.core.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionExpiredError,
    UserAlreadyExistsError,
)
from secure_auth.core.hasher import Argon2PasswordHasher, password_hasher
from secure_auth.core.tokens import generate_session_token, hash_token
from secure_auth.models.session import Session as UserSession
from secure_auth.models.user import User
from secure_auth.services.audit_service import AuditService
from secure_auth.services.lockout_service import LockoutService
from secure_auth.services.mfa_service import MFAService
from secure_auth.storage.repository import SessionRepository, UserRepository


class AuthService:
    """Orchestrates identity verification, timing defenses, session management, and audits."""

    def __init__(
        self,
        db_session: Session,
        hasher: Argon2PasswordHasher | None = None,
    ) -> None:
        self.db_session = db_session
        self.user_repo = UserRepository(db_session)
        self.session_repo = SessionRepository(db_session)
        self.lockout_service = LockoutService(db_session)
        self.audit_service = AuditService(db_session)
        self.mfa_service = MFAService(db_session)
        self.hasher = hasher or password_hasher

    def register(
        self,
        username: str,
        email: str,
        password: str,
        ip_address: str | None = None,
    ) -> User:
        """Register a new user account with hashed password.

        Args:
            username: Alphanumeric username.
            email: Valid email string.
            password: Plaintext password meeting security policy.
            ip_address: Client registration IP address.

        Returns:
            Newly created and persisted User entity.

        Raises:
            UserAlreadyExistsError: If username or email is already taken.
            ValueError: If password or identity is malformed.
        """
        clean_user = username.strip().lower()
        clean_email = email.strip().lower()

        if len(clean_user) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        if "@" not in clean_email or "." not in clean_email:
            raise ValueError("Invalid email format.")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")

        # Check existing collisions
        if self.user_repo.get_by_username(clean_user) or self.user_repo.get_by_email(clean_email):
            raise UserAlreadyExistsError()

        # Compute Argon2id hash
        pwd_hash = self.hasher.hash_password(password)

        user = self.user_repo.create(
            username=clean_user,
            email=clean_email,
            password_hash=pwd_hash,
        )

        self.audit_service.log(
            event_type="AUTH_REGISTER_SUCCESS",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            status="SUCCESS",
        )
        return user

    def authenticate(
        self,
        identifier: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, str, bool]:
        """Authenticate user credentials with timing side-channel mitigation.

        Args:
            identifier: Username or email.
            password: Provided plaintext password.
            ip_address: Client IP address.
            user_agent: Client User-Agent string.

        Returns:
            Tuple of (user, raw_token, is_mfa_required).
            If is_mfa_required is True, the raw_token is a temporary step-up token.

        Raises:
            InvalidCredentialsError: On incorrect identifier or password.
            AccountLockedError: When brute-force threshold is breached.
            AccountInactiveError: When account is deactivated.
        """
        clean_id = identifier.strip().lower()
        user = self.user_repo.get_by_identifier(clean_id)

        # Timing Defense: Run dummy password verification if user not found
        if user is None:
            self.hasher.verify_dummy()
            self.audit_service.log(
                event_type="AUTH_LOGIN_FAILURE",
                username=clean_id,
                ip_address=ip_address,
                status="FAILURE",
                details={"reason": "user_not_found"},
            )
            raise InvalidCredentialsError()

        # Check account status
        if not user.is_active:
            self.hasher.verify_dummy()
            raise AccountInactiveError()

        # Check lockout status
        is_locked, remaining_seconds = self.lockout_service.check_lockout(user)
        if is_locked:
            self.hasher.verify_dummy()
            self.audit_service.log(
                event_type="AUTH_ACCOUNT_LOCKED",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                status="WARNING",
                details={"remaining_seconds": remaining_seconds},
            )
            raise AccountLockedError(remaining_seconds)

        # Verify password with Argon2id
        is_valid = self.hasher.verify_password(user.password_hash, password)
        needs_rehash = is_valid and self.hasher.check_needs_rehash(user.password_hash)

        if not is_valid:
            now_locked, penalty_seconds = self.lockout_service.register_failure(user)
            if now_locked:
                self.audit_service.log(
                    event_type="AUTH_ACCOUNT_LOCKED",
                    user_id=user.id,
                    username=user.username,
                    ip_address=ip_address,
                    status="WARNING",
                    details={"penalty_seconds": penalty_seconds},
                )
                self.db_session.commit()
                raise AccountLockedError(penalty_seconds)

            self.audit_service.log(
                event_type="AUTH_LOGIN_FAILURE",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                status="FAILURE",
                details={"reason": "bad_password"},
            )
            self.db_session.commit()
            raise InvalidCredentialsError()

        # Password verified! Handle rehash if parameters upgraded
        if needs_rehash:
            user.password_hash = self.hasher.hash_password(password)
            self.user_repo.update(user)

        assert user.id is not None
        raw_token = generate_session_token(settings.SESSION_TOKEN_BYTES)
        token_digest = hash_token(raw_token)
        now = datetime.now(UTC)

        # Check if MFA is required
        if user.mfa_enabled:
            # Short-lived (5 min) unauthenticated challenge session
            challenge_expiry = now + timedelta(minutes=5)
            self.session_repo.create_session(
                user_id=user.id,
                token_hash=token_digest,
                expires_at=challenge_expiry,
                ip_address=ip_address,
                user_agent=user_agent,
                mfa_authenticated=False,
            )
            self.audit_service.log(
                event_type="MFA_CHALLENGE_REQUIRED",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                status="SUCCESS",
            )
            return user, raw_token, True

        # MFA not enabled: complete login and issue full session
        self.lockout_service.register_success(user)
        session_expiry = now + timedelta(hours=settings.SESSION_LIFETIME_HOURS)
        self.session_repo.create_session(
            user_id=user.id,
            token_hash=token_digest,
            expires_at=session_expiry,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_authenticated=True,
        )
        self.audit_service.log(
            event_type="AUTH_LOGIN_SUCCESS",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            status="SUCCESS",
            details={"mfa_used": False},
        )
        return user, raw_token, False

    def complete_mfa_login(
        self,
        mfa_token: str,
        code: str,
        ip_address: str | None = None,
    ) -> tuple[User, str]:
        """Validate MFA challenge and promote temporary token to full session.

        Args:
            mfa_token: Temporary step-up token issued during primary login.
            code: 6-digit TOTP code or emergency backup code.
            ip_address: Client verification IP.

        Returns:
            Tuple of (user, valid_session_token).

        Raises:
            InvalidTokenError: If MFA token is invalid, expired, or already used.
            InvalidMFACodeError: If code fails verification.
        """
        token_digest = hash_token(mfa_token)
        session = self.session_repo.get_by_token_hash(token_digest)
        now = datetime.now(UTC)

        if not session or session.is_revoked:
            raise InvalidTokenError()

        expiry = session.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)

        if expiry < now:
            raise SessionExpiredError()

        user = self.user_repo.get_by_id(session.user_id)
        if not user or not user.is_active:
            raise InvalidTokenError()

        # Validate code (raises InvalidMFACodeError on failure)
        self.mfa_service.verify_mfa_code(user, code)

        # Promote session to full active status
        session.mfa_authenticated = True
        session.expires_at = now + timedelta(hours=settings.SESSION_LIFETIME_HOURS)
        self.db_session.add(session)
        self.db_session.flush()

        # Reset failed login count
        self.lockout_service.register_success(user)

        self.audit_service.log(
            event_type="AUTH_LOGIN_SUCCESS",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            status="SUCCESS",
            details={"mfa_used": True},
        )
        return user, mfa_token

    def validate_session(self, raw_token: str) -> tuple[User, UserSession]:
        """Validate bearer token, check revocation and expiry, return authenticated user.

        Args:
            raw_token: Plaintext bearer token string.

        Returns:
            Tuple of (User, Session).

        Raises:
            InvalidTokenError: If token is unknown, revoked, or MFA not satisfied.
            SessionExpiredError: If token has expired.
        """
        token_digest = hash_token(raw_token)
        session = self.session_repo.get_by_token_hash(token_digest)
        now = datetime.now(UTC)

        if not session or session.is_revoked or not session.mfa_authenticated:
            raise InvalidTokenError()

        expiry = session.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)

        if expiry < now:
            raise SessionExpiredError()

        user = self.user_repo.get_by_id(session.user_id)
        if not user or not user.is_active:
            raise InvalidTokenError()

        return user, session

    def logout(self, raw_token: str) -> bool:
        """Revoke a single session token."""
        token_digest = hash_token(raw_token)
        revoked = self.session_repo.revoke_session(token_digest)
        if revoked:
            session = self.session_repo.get_by_token_hash(token_digest)
            if session:
                self.audit_service.log(
                    event_type="AUTH_LOGOUT",
                    user_id=session.user_id,
                    status="SUCCESS",
                )
        return revoked

    def logout_all(self, user_id: int) -> int:
        """Revoke all sessions for a user."""
        count = self.session_repo.revoke_all_user_sessions(user_id)
        self.audit_service.log(
            event_type="AUTH_SESSION_REVOKED",
            user_id=user_id,
            status="SUCCESS",
            details={"revoked_count": count},
        )
        return count
