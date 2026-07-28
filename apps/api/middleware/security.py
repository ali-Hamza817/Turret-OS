"""
apps.api.middleware.security
==============================
Security headers middleware for TURRET OS API.
Sets all required HTTP security headers on every response.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject security headers on all responses.

    Headers set:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Content-Security-Policy: strict policy
    - Strict-Transport-Security: 1 year with preload
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: disable unused browser features
    - Cache-Control: no-store for sensitive endpoints
    """

    async def dispatch(self, request: Request, call_next: any) -> Response:
        response: Response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "frame-ancestors 'none'; "
            "object-src 'none';"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Robots-Tag"] = "noindex"

        return response
