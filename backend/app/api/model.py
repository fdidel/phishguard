"""Model info and metrics endpoints."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from backend.app.core.config import settings
from backend.app.services.classifier import model_service
from backend.app.schemas.scan import (
    ModelInfoResponse,
    ModelMetricsResponse,
)

router = APIRouter(prefix="/api/v1/model", tags=["model"])

#: Path to the saved training-run metrics JSON.
_METRICS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abpath(__file__))),
    "..",
    "..",
    "ml",
    "artifacts",
    "model_metrics.json",
)


def _load_metrics() -> Dict[str, Any]:
    """Load the saved training-run metrics, returning an empty dict on failure."""
    if not os.path.exists(_METRICS_PATH):
        return {}
    try:
        with open(_METRICS_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


@router.get("/info", response_model=ModelInfoResponse)
async def model_info() -> ModelInfoResponse:
    """Return metadata about the loaded model."""
    info = model_service.info()
    return ModelInfoResponse(**info)


@router.get("/metrics", response_model=ModelMetricsResponse)
async def model_metrics() -> ModelMetricsResponse:
    """Return the saved evaluation metrics from the real training run."""
    metrics = _load_metrics()
    if not metrics:
        raise HTTPException(
            status_code=404,
            detail="Training-run metrics not found. Run 'python -m ml.src.train' first.",
        )
    return ModelMetricsResponse(**metrics)
