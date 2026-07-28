"""apps.api.routers.evidence — Evidence pack download endpoint."""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from apps.api.routers.alerts import require_api_key

logger = logging.getLogger(__name__)
router = APIRouter()

EVIDENCE_DIR = Path("evidence_packs")


@router.get("/{alert_id}/evidence.zip", dependencies=[Depends(require_api_key)])
async def get_evidence_pack(alert_id: UUID) -> FileResponse:
    """
    Stream the signed evidence ZIP for a given alert.

    Security:
    - alert_id validated as UUID (no path traversal possible).
    - File served from a fixed directory; no user-controlled path components.
    - Content-Disposition: attachment enforced.
    """
    # Construct path from validated UUID only — no user-supplied filename
    zip_path = EVIDENCE_DIR / f"{str(alert_id)}.zip"

    # Verify path is within evidence directory (defense in depth)
    try:
        resolved = zip_path.resolve()
        evidence_dir_resolved = EVIDENCE_DIR.resolve()
        if not str(resolved).startswith(str(evidence_dir_resolved) + "/"):
            raise HTTPException(status_code=400, detail="Invalid path")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid alert ID")

    if not zip_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence pack not found for alert {alert_id}",
        )

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{alert_id}.zip"',
            "X-Content-Type-Options": "nosniff",
        },
    )
