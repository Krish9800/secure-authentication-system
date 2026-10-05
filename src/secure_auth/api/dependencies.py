"""FastAPI dependency injection providers for database and security services."""

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from secure_auth.core.exceptions import InvalidTokenError, SessionExpiredError
from secure_auth.models.session import Session as UserSession
from secure_auth.models.user import User
from secure_auth.services.auth_service import AuthService
from secure_auth.services.mfa_service import MFAService
from secure_auth.storage.database import get_engine, init_db

# Shared default engine instance
_engine = get_engine()
init_db(_engine)

security_bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Yield transactional database session per request."""
    with Session(_engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def get_auth_service(session: Annotated[Session, Depends(get_db)]) -> AuthService:
    """Dependency providing initialized AuthService."""
    return AuthService(session)


def get_mfa_service(session: Annotated[Session, Depends(get_db)]) -> MFAService:
    """Dependency providing initialized MFAService."""
    return MFAService(session)


def get_current_user_and_session(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> tuple[User, UserSession]:
    """Extract and validate bearer token from request Authorization header.

    Returns:
        Tuple of (User, Session).

    Raises:
        HTTPException: If bearer token is missing, invalid, or expired.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user, user_session = auth_service.validate_session(credentials.credentials)
        return user, user_session
    except (InvalidTokenError, SessionExpiredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is invalid, revoked, or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_user(
    auth_data: Annotated[tuple[User, UserSession], Depends(get_current_user_and_session)],
) -> User:
    """Convenience dependency returning only authenticated User."""
    return auth_data[0]


def get_client_ip(request: Request) -> str:
    """Extract client IP address accounting for proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"
