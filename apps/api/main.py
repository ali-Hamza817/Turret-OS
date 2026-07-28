"""
TURRET OS API — FastAPI application.
Provides all L5 analyst workbench endpoints with:
- API key authentication on all routes
- Rate limiting via SlowAPI
- CORS, CSP, security headers middleware
- Async graph queries via Neo4j driver
"""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from apps.api.routers import alerts, evidence
from apps.api.middleware.security import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)

# ── Rate limiter ──────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("TURRET OS API starting up...")
    yield
    logger.info("TURRET OS API shutting down...")


# ── Application ───────────────────────────────────────────────────────────
app = FastAPI(
    title="TURRET OS API",
    description="Provenance Sentinel for Espionage-Grade Insider Detection",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────

# CORS — only allow configured origins
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
allowed_origins = [o.strip() for o in allowed_origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,    # Never wildcard *
    allow_credentials=True,
    allow_methods=["GET", "POST"],    # Principle of least privilege
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
app.include_router(evidence.router, prefix="/alerts", tags=["evidence"])


# ── Health ────────────────────────────────────────────────────────────────
@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "service": "turret-api", "version": "0.1.0"}
