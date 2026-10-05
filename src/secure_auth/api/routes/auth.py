"""Authentication endpoints: registration, primary login, step-up MFA, and logout."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from secure_auth.api.dependencies import (
    get_auth_service,
    get_client_ip,
    get_current_user_and_session,
    security_bearer,
)
from secure_auth.api.schemas import (
    LoginRequest,
    LoginResponse,
    MessageResponse,
    MFAVerifyRequest,
    RegisterRequest,
    RegisterResponse,
)
from secure_auth.models.session import Session as UserSession
from secure_auth.models.user import User
from secure_auth.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    payload: RegisterRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> RegisterResponse:
    """Register a new account with Argon2id password hashing."""
    client_ip = get_client_ip(request)
    user = auth_service.register(
        username=payload.username,
        email=payload.email,
        password=payload.password,
        ip_address=client_ip,
    )
    return RegisterResponse(
        uuid=user.uuid,
        username=user.username,
        email=user.email,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate with username/email and password",
)
def login(
    payload: LoginRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """Authenticate user with timing attack mitigation and brute-force defenses."""
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    _, raw_token, mfa_required = auth_service.authenticate(
        identifier=payload.username_or_email,
        password=payload.password,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    if mfa_required:
        return LoginResponse(
            status="mfa_required",
            token=raw_token,
            mfa_required=True,
            message="Primary authentication successful. Secondary factor challenge required.",
        )

    return LoginResponse(
        status="authenticated",
        token=raw_token,
        mfa_required=False,
        message="Authentication successful.",
    )


@router.post(
    "/mfa/verify",
    response_model=LoginResponse,
    summary="Complete multi-factor challenge to obtain active session",
)
def verify_mfa_step(
    payload: MFAVerifyRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """Validate TOTP or single-use recovery code to promote challenge token to full session."""
    client_ip = get_client_ip(request)
    _, session_token = auth_service.complete_mfa_login(
        mfa_token=payload.mfa_token,
        code=payload.code,
        ip_address=client_ip,
    )
    return LoginResponse(
        status="authenticated",
        token=session_token,
        mfa_required=False,
        message="Multi-factor challenge satisfied. Session established.",
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke the active bearer session",
)
def logout(
    _auth_data: Annotated[tuple[User, UserSession], Depends(get_current_user_and_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> MessageResponse:
    """Revoke current bearer session token immediately."""
    if credentials and credentials.credentials:
        auth_service.logout(credentials.credentials)
    return MessageResponse(message="Session successfully revoked.")


@router.post(
    "/logout-all",
    response_model=MessageResponse,
    summary="Revoke all active sessions across all devices for the current user",
)
def logout_all(
    auth_data: Annotated[tuple[User, UserSession], Depends(get_current_user_and_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> MessageResponse:
    """Revoke all sessions for current user."""
    user, _ = auth_data
    assert user.id is not None
    count = auth_service.logout_all(user.id)
    return MessageResponse(
        message="All sessions revoked.",
        detail=f"Revoked {count} active sessions.",
    )
