"""Health endpoint."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from backend.app.core.config import settings
from backend.app.database.base import engine
from backend.app.services.classifier import model_service
from backend.app.schemas.scan import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Service health probe."""
    try:
        engine.connect()
        db_ok = True
    except Exception:
        db_ok = False

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version=settings.app_name,
        environment=settings.environment,
        model_loaded=model_service.is_loaded,
        model_version=model_service._artifact.get("model_version") if model_service.is_loaded else None,
        database="ok" if db_ok else "error",
        page_analysis_enabled=settings.page_analysis_enabled,
        threat_intel_enabled=settings.threat_intel_enabled,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
