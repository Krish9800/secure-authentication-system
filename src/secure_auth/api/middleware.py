"""Security middleware: defensive HTTP headers and sliding-window IP rate limiting."""

import time
from collections import defaultdict

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from secure_auth.config.settings import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies strict defensive security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response: Response = await call_next(request)

        # Defense-in-depth security response headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding window rate limiter per client IP address."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        # Dictionary mapping IP to list of request timestamps
        self.auth_requests: dict[str, list[float]] = defaultdict(list)
        self.global_requests: dict[str, list[float]] = defaultdict(list)

    def _clean_and_count(
        self, timestamps: list[float], window_seconds: float = 60.0
    ) -> tuple[list[float], int]:
        """Prune timestamps older than window and return updated list and count."""
        now = time.time()
        cutoff = now - window_seconds
        active = [ts for ts in timestamps if ts > cutoff]
        return active, len(active)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        path = request.url.path

        # 1. Global rate limit check
        active_global, count_global = self._clean_and_count(self.global_requests[client_ip])
        if count_global >= settings.RATE_LIMIT_GLOBAL_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": "Global IP request limit exceeded. Please back off.",
                },
                headers={"Retry-After": "60"},
            )
        active_global.append(now)
        self.global_requests[client_ip] = active_global

        # 2. Sensitive auth endpoints limit (/login, /register)
        if any(auth_path in path for auth_path in ("/login", "/register")):
            active_auth, count_auth = self._clean_and_count(self.auth_requests[client_ip])
            if count_auth >= settings.RATE_LIMIT_AUTH_PER_MINUTE:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "detail": "Authentication attempt rate limit exceeded for this IP.",
                    },
                    headers={"Retry-After": "60"},
                )
            active_auth.append(now)
            self.auth_requests[client_ip] = active_auth

        return await call_next(request)
