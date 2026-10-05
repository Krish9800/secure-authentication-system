"""FastAPI application factory and security configuration."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from secure_auth.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from secure_auth.api.routes import auth_router, mfa_router, users_router
from secure_auth.config.settings import settings
from secure_auth.core.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AuthError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    InvalidTokenError,
    SessionExpiredError,
    UserAlreadyExistsError,
)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Production-grade defensive authentication service featuring Argon2id, "
            "RFC 6238 TOTP 2FA, progressive brute-force lockout, and side-channel timing defenses."
        ),
        version="0.1.0",
        docs_url="/docs" if settings.DEBUG else "/docs",
        redoc_url="/redoc" if settings.DEBUG else None,
    )

    # Attach Defensive Middlewares (outermost executes first)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # Exception Handlers
    @app.exception_handler(InvalidCredentialsError)
    async def invalid_credentials_handler(_: Request, exc: InvalidCredentialsError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "detail": exc.message},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(AccountLockedError)
    async def account_locked_handler(_: Request, exc: AccountLockedError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_423_LOCKED,
            content={
                "error": "AccountLocked",
                "detail": exc.message,
                "remaining_seconds": exc.remaining_seconds,
            },
            headers={"Retry-After": str(exc.remaining_seconds)},
        )

    @app.exception_handler(AccountInactiveError)
    async def account_inactive_handler(_: Request, exc: AccountInactiveError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Forbidden", "detail": exc.message},
        )

    @app.exception_handler(UserAlreadyExistsError)
    async def user_exists_handler(_: Request, exc: UserAlreadyExistsError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "detail": exc.message},
        )

    @app.exception_handler(InvalidTokenError)
    async def invalid_token_handler(_: Request, exc: InvalidTokenError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "detail": exc.message},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(SessionExpiredError)
    async def session_expired_handler(_: Request, exc: SessionExpiredError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "detail": exc.message},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(InvalidMFACodeError)
    async def invalid_mfa_code_handler(_: Request, exc: InvalidMFACodeError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "BadRequest", "detail": exc.message},
        )

    @app.exception_handler(AuthError)
    async def general_auth_handler(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "AuthError", "detail": exc.message},
        )

    # Health check
    @app.get("/health", tags=["Health"], summary="Service health check")
    def health_check() -> dict[str, str]:
        return {
            "status": "healthy",
            "service": settings.APP_NAME,
            "version": "0.1.0",
        }

    # Mount API routers
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(mfa_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")

    return app


app = create_app()
