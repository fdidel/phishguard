"""Reporting endpoints: aggregate summary and CSV export."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.database.base import get_db
from backend.app.models.scan import Scan
from backend.app.schemas.scan import ReportSummaryResponse

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _summary_rows(db: Session) -> List[Dict[str, Any]]:
    """Fetch every scan row (already bounded by the retention policy)."""
    stmt = select(Scan).order_by(Scan.created_at.desc())
    return [dict(row._mapping) for row in db.execute(stmt).mappings().all()]


@router.get("/summary", response_model=ReportSummaryResponse)
async def reports_summary(db: Session = Depends(get_db)) -> ReportSummaryResponse:
    """Return aggregate statistics across the scan history."""
    by_status: Dict[str, int] = {}
    by_classification: Dict[str, int] = {}
    domains = set()
    risk_values: List[int] = []
    total = 0

    for row in _summary_rows(db):
        total += 1
        status_value = row.get("status") or "unknown"
        classification = row.get("classification") or "unknown"
        by_status[status_value] = by_status.get(status_value, 0) + 1
        by_classification[classification] = by_classification.get(classification, 0) + 1
        if row.get("registrable_domain"):
            domains.add(row["registrable_domain"])
        risk = row.get("risk_score")
        if risk is not None:
            risk_values.append(int(risk))

    return ReportSummaryResponse(
        total_scans=total,
        by_status=by_status,
        by_classification=by_classification,
        average_risk_score=round(sum(risk_values) / len(risk_values), 2)
        if risk_values
        else None,
        dangerous_scans=by_classification.get("dangerous", 0),
        suspicious_scans=by_classification.get("suspicious", 0),
        safe_scans=by_classification.get("safe", 0),
        failed_scans=by_status.get("failed", 0),
        unique_domains=len(domains),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/export.csv")
async def export_scans_csv(
    limit: int = Query(5000, ge=1, le=100000),
    db: Session = Depends(get_db),
) -> Response:
    """Export the scan history as CSV.

    The export contains only the analysis metadata.  No credentials, cookies
    or page content are ever stored, so nothing sensitive can leak through it.
    """
    rows = _summary_rows(db)[:limit]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "scan_id",
            "created_at",
            "submitted_url",
            "normalized_url",
            "hostname",
            "registrable_domain",
            "status",
            "classification",
            "phishing_probability",
            "risk_score",
            "model_version",
            "duration_ms",
        ]
    )
    for row in rows:
        created = row.get("created_at")
        writer.writerow(
            [
                row.get("id", ""),
                created.isoformat() if created else "",
                row.get("submitted_url", ""),
                row.get("normalized_url", ""),
                row.get("hostname", ""),
                row.get("registrable_domain", ""),
                row.get("status", ""),
                row.get("classification", ""),
                "" if row.get("phishing_probability") is None else row["phishing_probability"],
                "" if row.get("risk_score") is None else row["risk_score"],
                row.get("model_version", ""),
                "" if row.get("duration_ms") is None else row["duration_ms"],
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=phishguard-scans.csv"
        },
    )
