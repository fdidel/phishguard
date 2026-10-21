"""User feedback endpoint."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.base import get_db
from backend.app.models.scan import Feedback, Scan
from backend.app.schemas.scan import ErrorResponse, FeedbackRequest, FeedbackResponse

router = APIRouter(prefix="/api/v1", tags=["feedback"])


@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    responses={404: {"model": ErrorResponse}},
)
async def submit_feedback(
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
) -> FeedbackResponse:
    """Record user feedback about a prediction."""
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{payload.scan_id}' not found.",
        )

    record = Feedback(
        scan_id=payload.scan_id,
        is_correct=payload.is_correct,
        correct_classification=payload.correct_classification,
        comment=payload.comment,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return FeedbackResponse(
        feedback_id=record.id,
        scan_id=record.scan_id,
        recorded_at=record.created_at or datetime.now(timezone.utc),
    )
