"""Single-scan submission endpoint: POST /api/v1/scan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.base import get_db
from backend.app.schemas.scan import ErrorResponse, ScanRequest, ScanResult
from backend.app.services.scanner import perform_scan

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])


@router.post(
    "",
    response_model=ScanResult,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def create_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
) -> ScanResult:
    """Submit a URL for analysis and return the structured result."""
    outcome = perform_scan(
        raw_url=payload.url,
        db=db,
        include_page_analysis=payload.include_page_analysis,
        store_result=payload.store_result,
    )
    return ScanResult(**outcome.to_dict())
