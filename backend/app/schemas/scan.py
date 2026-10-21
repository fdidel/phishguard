"""Pydantic request/response schemas for the public API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.config import settings


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request body for ``POST /api/v1/scan``."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        ...,
        min_length=1,
        max_length=settings.max_url_length,
        description="The HTTP(S) address to analyse.",
        examples=["https://example.com/login"],
    )
    include_page_analysis: bool = Field(
        default=False,
        description=(
            "Optionally fetch and analyse the page content. Disabled by default "
            "because it makes the backend contact the submitted site."
        ),
    )
    store_result: bool = Field(
        default=True, description="Whether the scan should be recorded in the history."
    )

    @field_validator("url")
    @classmethod
    def _strip(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("The URL must not be empty.")
        return stripped


class FeedbackRequest(BaseModel):
    """Request body for ``POST /api/v1/feedback``."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1, max_length=64)
    is_correct: bool = Field(..., description="Whether the prediction was correct.")
    correct_classification: Optional[str] = Field(
        default=None,
        description="The classification the user believes is correct.",
    )
    comment: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("correct_classification")
    @classmethod
    def _valid_classification(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        allowed = {"safe", "suspicious", "dangerous", "inconclusive"}
        lowered = value.strip().lower()
        if lowered not in allowed:
            raise ValueError(
                f"correct_classification must be one of {sorted(allowed)}."
            )
        return lowered


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------


class Indicator(BaseModel):
    """A single piece of evidence supporting a verdict."""

    category: str
    value: float = 0.0
    description: str


class FeatureContribution(BaseModel):
    """Contribution estimate for one feature in one prediction."""

    feature: str
    value: float
    global_importance: float
    contribution: float


class Explanation(BaseModel):
    """The explanation attached to a scan result."""

    evidence: List[Indicator] = Field(default_factory=list)
    top_contributing_features: List[FeatureContribution] = Field(default_factory=list)
    note: str


class ScanResult(BaseModel):
    """The structured result of a website safety verification."""

    scan_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    registrable_domain: str

    status: str = Field(
        ..., description="completed | inconclusive | failed"
    )
    analysis_coverage: str = Field(
        ..., description="url_only | url_and_page"
    )
    classification: str = Field(
        ..., description="safe | suspicious | dangerous | inconclusive | unknown"
    )
    classification_label: str
    guidance: str

    risk_score: Optional[int] = Field(
        default=None,
        description="0-100 relative risk indicator derived from the calibrated probability.",
    )
    phishing_probability: Optional[float] = Field(
        default=None, description="Calibrated probability that the URL is a phishing URL."
    )

    indicators: List[Indicator] = Field(default_factory=list)
    explanation: Optional[Explanation] = None
    warnings: List[str] = Field(default_factory=list)

    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    model_algorithm: Optional[str] = None

    threat_intelligence: Optional[Dict[str, Any]] = None
    page_analysis: Optional[Dict[str, Any]] = None

    scanned_at: datetime
    duration_ms: Optional[int] = None
    limitations: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """A compact scan record used in the history list."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    status: str
    classification: str
    risk_score: Optional[int] = None
    phishing_probability: Optional[float] = None
    model_version: Optional[str] = None
    scanned_at: datetime
    duration_ms: Optional[int] = None


class ScanDetail(ScanSummary):
    """Full detail of a single scan."""

    registrable_domain: str = ""
    analysis_coverage: str = "url_only"
    classification_label: str = ""
    guidance: str = ""
    indicators: List[Indicator] = Field(default_factory=list)
    explanation: Optional[Explanation] = None
    warnings: List[str] = Field(default_factory=list)
    feature_schema_version: Optional[str] = None
    features: Optional[Dict[str, float]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
    page_analysis: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class PaginatedScans(BaseModel):
    """A page of scan history."""

    items: List[ScanSummary]
    total: int
    page: int
    page_size: int
    pages: int


class FeedbackResponse(BaseModel):
    """Confirmation that feedback was recorded."""

    feedback_id: str
    scan_id: str
    recorded_at: datetime


class HealthResponse(BaseModel):
    """Service health."""

    status: str
    version: str
    environment: str
    model_loaded: bool
    model_version: Optional[str] = None
    database: str
    page_analysis_enabled: bool
    threat_intel_enabled: bool
    timestamp: datetime


class ModelInfoResponse(BaseModel):
    """Metadata about the loaded model."""

    available: bool
    model_version: Optional[str] = None
    feature_schema_version: str
    algorithm: Optional[str] = None
    trained_at: Optional[str] = None
    random_seed: Optional[int] = None
    thresholds: Dict[str, float] = Field(default_factory=dict)
    feature_count: int = 0
    supported_features: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class ModelMetricsResponse(BaseModel):
    """Saved evaluation metrics from the real training run."""

    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    selected_model: Optional[str] = None
    trained_at: Optional[str] = None
    random_seed: Optional[int] = None
    dataset: Dict[str, Any] = Field(default_factory=dict)
    split: Dict[str, Any] = Field(default_factory=dict)
    thresholds: Dict[str, float] = Field(default_factory=dict)
    test_set: Dict[str, Any] = Field(default_factory=dict)
    model_comparison: List[Dict[str, Any]] = Field(default_factory=list)
    feature_importance: List[Dict[str, Any]] = Field(default_factory=list)
    inference_latency: Dict[str, Any] = Field(default_factory=dict)
    environment: Dict[str, Any] = Field(default_factory=dict)


class ReportSummaryResponse(BaseModel):
    """Aggregate statistics across the scan history."""

    total_scans: int
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_classification: Dict[str, int] = Field(default_factory=dict)
    average_risk_score: Optional[float] = None
    dangerous_scans: int = 0
    suspicious_scans: int = 0
    safe_scans: int = 0
    failed_scans: int = 0
    unique_domains: int = 0
    generated_at: datetime


class ErrorResponse(BaseModel):
    """Uniform error body."""

    error: str
    message: str
    detail: Optional[Any] = None
