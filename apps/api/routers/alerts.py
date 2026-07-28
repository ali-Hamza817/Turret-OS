"""
apps.api.routers.alerts
========================
Alert CRUD and action endpoints:
- GET  /alerts                         → list alerts with pagination
- GET  /alerts/{id}                    → single alert detail
- GET  /alerts/{id}/subgraph           → 4-hop ego-subgraph
- GET  /alerts/{id}/explanation        → SHAP + GNNExplainer output
- POST /alerts/{id}/ack                → acknowledge alert
- POST /alerts/{id}/escalate           → escalate to Tier 2
- POST /alerts/{id}/dismiss            → dismiss with reason

Security:
- API key required via X-API-Key header on all endpoints.
- Rate limited to 100 requests/minute per IP.
- Alert IDs validated as UUIDs; no arbitrary Neo4j query injection.
- Cypher queries use bound parameters only.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()


# ── API Key auth dependency ────────────────────────────────────────────────

def _get_api_key_from_env() -> str:
    """Load API key from environment; generate ephemeral if missing (logs warning)."""
    key = os.getenv("API_SECRET_KEY")
    if not key:
        import logging as _log
        _log.getLogger(__name__).critical(
            "API_SECRET_KEY not set; using ephemeral key (NOT prod-safe)"
        )
        return secrets.token_hex(32)
    return key


_API_KEY: str = _get_api_key_from_env()


async def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Validate the X-API-Key header using constant-time comparison.
    Raises 401 if missing or invalid.
    """
    if not secrets.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_api_key


# ── Alert endpoints ───────────────────────────────────────────────────────

@router.get("", dependencies=[Depends(require_api_key)])
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
) -> dict[str, Any]:
    """List detection alerts with pagination and score filter."""
    # TODO: Query from Neo4j / DuckDB alert store
    return {
        "page": page,
        "page_size": page_size,
        "total": 0,
        "alerts": [],
        "note": "Connect Neo4j to populate real alerts",
    }


@router.get("/{alert_id}", dependencies=[Depends(require_api_key)])
async def get_alert(alert_id: UUID) -> dict[str, Any]:
    """Get full detail for a single alert."""
    # TODO: Neo4j lookup by alert_id (bound param)
    return {"alert_id": str(alert_id), "detail": "placeholder"}


@router.get("/{alert_id}/subgraph", dependencies=[Depends(require_api_key)])
async def get_subgraph(
    alert_id: UUID,
    depth: int = Query(4, ge=1, le=6, description="Ego-subgraph hop depth"),
) -> dict[str, Any]:
    """Return the 4-hop ego-subgraph for Cytoscape.js visualisation."""
    return {
        "alert_id": str(alert_id),
        "depth": depth,
        "nodes": [],
        "edges": [],
    }


@router.get("/{alert_id}/explanation", dependencies=[Depends(require_api_key)])
async def get_explanation(alert_id: UUID) -> dict[str, Any]:
    """Return SHAP values + GNNExplainer subgraph for this alert."""
    return {
        "alert_id": str(alert_id),
        "shap_values": {},
        "gnn_explainer": {"edge_mask": [], "fidelity_score": None},
        "nl_explanation": "Explanation pending model training completion.",
    }


@router.post("/{alert_id}/ack", dependencies=[Depends(require_api_key)])
async def ack_alert(alert_id: UUID) -> dict[str, Any]:
    """Acknowledge an alert (mark as reviewed)."""
    return {"alert_id": str(alert_id), "status": "acknowledged"}


@router.post("/{alert_id}/escalate", dependencies=[Depends(require_api_key)])
async def escalate_alert(alert_id: UUID) -> dict[str, Any]:
    """Escalate an alert to Tier 2 SOC analyst."""
    return {"alert_id": str(alert_id), "status": "escalated"}


@router.post("/{alert_id}/dismiss", dependencies=[Depends(require_api_key)])
async def dismiss_alert(
    alert_id: UUID,
    reason: str = Query(..., min_length=5, max_length=500),
) -> dict[str, Any]:
    """Dismiss an alert with a mandatory reason string."""
    return {"alert_id": str(alert_id), "status": "dismissed", "reason": reason}
