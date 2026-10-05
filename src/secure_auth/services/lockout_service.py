"""Account lockout and brute-force mitigation service."""

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from secure_auth.config.settings import settings
from secure_auth.models.user import User
from secure_auth.storage.repository import UserRepository


class LockoutService:
    """Service enforcing progressive exponential lockouts on consecutive authentication failures."""

    def __init__(self, db_session: Session) -> None:
        self.db_session = db_session
        self.user_repo = UserRepository(db_session)

    def check_lockout(self, user: User) -> tuple[bool, int]:
        """Check if an account is currently locked out.

        Args:
            user: User entity to inspect.

        Returns:
            Tuple of (is_locked: bool, remaining_seconds: int).
        """
        now = datetime.now(UTC)

        # Handle active lockout timestamp
        if user.locked_until is not None:
            # Normalize to UTC for comparison
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=UTC)

            if now < locked_until:
                remaining = max(1, int((locked_until - now).total_seconds()))
                return True, remaining
            else:
                # Lockout duration has expired; clear lockout
                self.user_repo.reset_failed_attempts(user)
                return False, 0

        # Handle stale failure counter reset window
        last_updated = user.updated_at
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=UTC)

        reset_delta = timedelta(seconds=settings.FAILED_ATTEMPTS_RESET_WINDOW_SECONDS)
        if user.failed_login_attempts > 0 and (now - last_updated) > reset_delta:
            self.user_repo.reset_failed_attempts(user)

        return False, 0

    def register_failure(self, user: User) -> tuple[bool, int]:
        """Record an authentication failure and compute progressive lockout penalty.

        Args:
            user: User entity experiencing failed login.

        Returns:
            Tuple of (now_locked: bool, lockout_seconds: int).
        """
        now = datetime.now(UTC)
        new_attempts = user.failed_login_attempts + 1

        if new_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            # Exponential progressive backoff: 2^(excess_attempts)
            excess = new_attempts - settings.MAX_FAILED_LOGIN_ATTEMPTS
            multiplier = 2**excess
            penalty_seconds = min(
                settings.LOCKOUT_BASE_DURATION_SECONDS * multiplier,
                settings.MAX_LOCKOUT_DURATION_SECONDS,
            )
            locked_until = now + timedelta(seconds=penalty_seconds)
            self.user_repo.increment_failed_attempts(user, locked_until=locked_until)
            return True, penalty_seconds
        else:
            self.user_repo.increment_failed_attempts(user)
            return False, 0

    def register_success(self, user: User) -> None:
        """Clear failed login attempts counter upon successful authentication.

        Args:
            user: User entity that successfully authenticated.
        """
        if user.failed_login_attempts > 0 or user.locked_until is not None:
            self.user_repo.reset_failed_attempts(user)

    def unlock_user(self, user: User) -> None:
        """Manually unlock an account (administrative override).

        Args:
            user: User entity to unlock.
        """
        self.user_repo.reset_failed_attempts(user)
