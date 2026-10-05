"""MFA management endpoints: setup enrollment, confirmation, and safe disabling."""

from typing import Annotated

from fastapi import APIRouter, Depends

from secure_auth.api.dependencies import (
    get_current_user,
    get_mfa_service,
)
from secure_auth.api.schemas import (
    MessageResponse,
    MFAConfirmRequest,
    MFADisableRequest,
    MFASetupResponse,
)
from secure_auth.models.user import User
from secure_auth.services.mfa_service import MFAService

router = APIRouter(prefix="/mfa", tags=["Multi-Factor Authentication"])


@router.post(
    "/setup",
    response_model=MFASetupResponse,
    summary="Generate TOTP secret and emergency backup recovery codes",
)
def setup_mfa(
    current_user: Annotated[User, Depends(get_current_user)],
    mfa_service: Annotated[MFAService, Depends(get_mfa_service)],
) -> MFASetupResponse:
    """Initiate MFA setup, returning base32 secret, otpauth provisioning URI, and backup codes."""
    secret, uri, codes = mfa_service.setup_mfa(current_user)
    return MFASetupResponse(
        secret=secret,
        provisioning_uri=uri,
        backup_recovery_codes=codes,
    )


@router.post(
    "/confirm",
    response_model=MessageResponse,
    summary="Confirm authenticator setup with a live TOTP code",
)
def confirm_mfa(
    payload: MFAConfirmRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    mfa_service: Annotated[MFAService, Depends(get_mfa_service)],
) -> MessageResponse:
    """Validate initial TOTP code to permanently activate MFA on the account."""
    mfa_service.confirm_mfa(current_user, payload.code)
    return MessageResponse(message="Multi-factor authentication successfully enabled.")


@router.post(
    "/disable",
    response_model=MessageResponse,
    summary="Safely disable multi-factor authentication with proof of possession",
)
def disable_mfa(
    payload: MFADisableRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    mfa_service: Annotated[MFAService, Depends(get_mfa_service)],
) -> MessageResponse:
    """Disable MFA after verifying current TOTP or backup recovery code."""
    mfa_service.disable_mfa(current_user, payload.code)
    return MessageResponse(message="Multi-factor authentication successfully disabled.")
