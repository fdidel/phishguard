"""Scan endpoints: submit, list, detail."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.database.base import get_db
from backend.app.models.scan import Classification, Scan, ScanStatus
from backend.app.schemas.scan import (
    ErrorResponse,
    PaginatedScans,
    ScanDetail,
    ScanRequest,
    ScanResult,
    ScanSummary,
)
from backend.app.services.scanner import perform_scan

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

#: Valid values for the ``status`` query filter.
VALID_STATUSES = {ScanStatus.COMPLETED, ScanStatus.INCONCLUSIVE, ScanStatus.FAILED}

#: Valid values for the ``classification`` query filter.
VALID_CLASSIFICATIONS = {
    Classification.SAFE,
    Classification.SUSPICIOUS,
    Classification.DANGEROUS,
    Classification.INCONCLUSIVE,
    Classification.UNKNOWN,
}


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


@router.get("", response_model=PaginatedScans)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    classification: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> PaginatedScans:
    """List scan history with optional filters and pagination."""
    if status_filter is not None and status_filter not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"status must be one of {sorted(VALID_STATUSES)}.",
        )
    if classification is not None and classification not in VALID_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"classification must be one of {sorted(VALID_CLASSIFICATIONS)}.",
        )

    conditions = []
    if status_filter:
        conditions.append(Scan.status == status_filter)
    if classification:
        conditions.append(Scan.classification == classification)
    if domain:
        conditions.append(Scan.registrable_domain == domain)
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            (Scan.submitted_url.ilike(pattern)) | (Scan.hostname.ilike(pattern))
        )

    count_stmt = select(func.count()).select_from(Scan)
    for cond in conditions:
        count_stmt = count_stmt.where(cond)
    total = db.execute(count_stmt).scalar() or 0

    stmt = (
        select(Scan)
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    for cond in conditions:
        stmt = stmt.where(cond)
    rows = db.execute(stmt).scalars().all()
    items = [ScanSummary.model_validate(row) for row in rows]

    pages = (total + page_size - 1) // page_size
    return PaginatedScans(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetail,
    responses={
        404: {"model": ErrorResponse},
    },
)
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanDetail:
    """Return the full detail of a single scan."""
    record = db.get(Scan, scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return ScanDetail.model_validate(record)
