"""API routes package."""

from secure_auth.api.routes.auth import router as auth_router
from secure_auth.api.routes.mfa import router as mfa_router
from secure_auth.api.routes.users import router as users_router

__all__ = [
    "auth_router",
    "mfa_router",
    "users_router",
]
