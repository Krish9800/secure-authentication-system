"""Domain-specific security exceptions for authentication workflows."""


class AuthError(Exception):
    """Base exception for authentication and authorization errors."""

    def __init__(self, message: str = "Authentication error occurred.") -> None:
        super().__init__(message)
        self.message = message


class InvalidCredentialsError(AuthError):
    """Raised when authentication credentials fail validation.

    Note: Always use generic messaging to prevent account enumeration.
    """

    def __init__(self, message: str = "Invalid username or password.") -> None:
        super().__init__(message)


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked due to excessive failed attempts."""

    def __init__(
        self,
        remaining_seconds: int,
        message: str = "Account is temporarily locked. Please try again later.",
    ) -> None:
        super().__init__(message)
        self.remaining_seconds = remaining_seconds


class AccountInactiveError(AuthError):
    """Raised when an account is disabled or deactivated."""

    def __init__(self, message: str = "Account is inactive or disabled.") -> None:
        super().__init__(message)


class UserAlreadyExistsError(AuthError):
    """Raised when registration conflicts with an existing identity."""

    def __init__(self, message: str = "Username or email is already registered.") -> None:
        super().__init__(message)


class InvalidTokenError(AuthError):
    """Raised when a session or verification token is malformed, invalid, or revoked."""

    def __init__(self, message: str = "Authentication token is invalid or revoked.") -> None:
        super().__init__(message)


class SessionExpiredError(AuthError):
    """Raised when a session has passed its expiration window."""

    def __init__(self, message: str = "Session has expired. Please authenticate again.") -> None:
        super().__init__(message)


class MFARequiredError(AuthError):
    """Raised when primary authentication succeeds but multi-factor challenge is pending."""

    def __init__(
        self,
        mfa_session_token: str,
        message: str = "Multi-factor authentication challenge required.",
    ) -> None:
        super().__init__(message)
        self.mfa_session_token = mfa_session_token


class InvalidMFACodeError(AuthError):
    """Raised when a TOTP or backup recovery code is invalid or already consumed."""

    def __init__(self, message: str = "Invalid or expired multi-factor code.") -> None:
        super().__init__(message)
