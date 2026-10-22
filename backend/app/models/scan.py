"""SQLAlchemy ORM models for scan history, feedback and evaluation metadata."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str):
    """Status constants for a scan record."""

    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class Classification(str):
    """Classification constants for a scan record."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    INCONCLUSIVE = "inconclusive"
    UNKNOWN = "unknown"


class Scan(Base):
    """A single website safety verification request and its outcome."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    #: Exactly what the user submitted (kept verbatim for reporting).
    submitted_url: Mapped[str] = mapped_column(Text, nullable=False)
    #: The normalised URL that was actually analysed.
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    #: Hostname of the analysed URL (denormalised for fast filtering).
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    #: Registrable domain, used for grouping scans.
    registrable_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=ScanStatus.COMPLETED, index=True)
    analysis_coverage: Mapped[str] = mapped_column(String(32), nullable=False, default="url_only")

    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default=Classification.UNKNOWN, index=True
    )
    #: Calibrated probability that the URL is phishing (0..1).
    phishing_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    #: 0-100 operational risk score derived from the calibrated probability.
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    model_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    feature_schema_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    #: Extracted feature values (name -> value), for reproducibility.
    features: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    #: Human-readable evidence indicators supporting the verdict.
    indicators: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    #: Non-fatal warnings raised during the scan.
    warnings: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    feedback: Mapped[List["Feedback"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_scans_created_classification", "created_at", "classification"),
        Index("ix_scans_status_created", "status", "created_at"),
    )


class Feedback(Base):
    """Optional user feedback about a prediction."""

    __tablename__ = "feedback"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: True when the user confirms the prediction was correct.
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    #: The classification the user believes is correct.
    correct_classification: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="feedback")


class ModelEvaluation(Base):
    """Metadata describing a completed training run (Objective 1 & 3)."""

    __tablename__ = "model_evaluations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    selected_model: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    dataset_license: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_source_url: Mapped[str] = mapped_column(Text, nullable=False)
    records_used: Mapped[int] = mapped_column(Integer, nullable=False)
    test_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    roc_auc: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    false_negative_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    #: Full metrics payload as produced by the training run.
    metrics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )


class DatasetSource(Base):
    """Provenance record for every dataset used by the project."""

    __tablename__ = "dataset_sources"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    license: Mapped[str] = mapped_column(String(128), nullable=False)
    retrieval_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    record_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    checksum_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
