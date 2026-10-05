"""User profile and account introspection endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlmodel import Session

from secure_auth.api.dependencies import get_current_user, get_db
from secure_auth.api.schemas import AuditEventResponse, UserProfileResponse
from secure_auth.models.user import User
from secure_auth.services.audit_service import AuditService

router = APIRouter(prefix="/users", tags=["User Profile"])


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get authenticated user profile",
)
def get_my_profile(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserProfileResponse:
    """Return user profile attributes for currently authenticated bearer token."""
    return UserProfileResponse(
        uuid=current_user.uuid,
        username=current_user.username,
        email=current_user.email,
        mfa_enabled=current_user.mfa_enabled,
        created_at=current_user.created_at,
    )


@router.get(
    "/me/audit",
    response_model=list[AuditEventResponse],
    summary="Get security audit history for the authenticated user",
)
def get_my_audit_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[AuditEventResponse]:
    """Retrieve personal audit log records."""
    assert current_user.id is not None
    audit_service = AuditService(db)
    events = audit_service.get_user_events(current_user.id, limit=50)
    return [
        AuditEventResponse(
            id=e.id or 0,
            timestamp=e.timestamp,
            event_type=e.event_type,
            status=e.status,
            details=e.details_json,
        )
        for e in events
    ]
