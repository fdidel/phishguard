"""
Scan orchestration.

The scanner is the single entry point used by the API.  It performs, in
order:

1. URL validation and normalisation (:mod:`phishguard.url_validation`),
2. feature extraction (:mod:`phishguard.feature_extraction`),
3. model inference (:mod:`backend.app.services.classifier`),
4. risk categorisation (:mod:`backend.app.services.risk_scoring`),
5. explanation generation (:mod:`backend.app.services.explainability`),
6. optional threat-intelligence lookup,
7. optional page-content analysis (SSRF-protected),
8. persistence of the scan record.

Failure handling is explicit at every step: a failure produces an
``inconclusive`` or ``failed`` status with an error code - never a safe
verdict.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.scan import Classification, Scan, ScanStatus
from backend.app.services import threat_intelligence
from backend.app.services.classifier import ModelUnavailableError, model_service
from backend.app.services.explainability import explain_prediction
from backend.app.services.risk_scoring import (
    DANGEROUS,
    INCONCLUSIVE,
    SAFE,
    SUSPICIOUS,
    UNKNOWN,
    categorize,
    inconclusive_assessment,
)
from phishguard.feature_extraction import extract_features
from phishguard.feature_schema import FEATURE_SCHEMA_VERSION
from phishguard.url_validation import UrlValidationError, validate_url

logger = logging.getLogger(__name__)


def _redact_userinfo(url: str) -> str:
    """Return a copy of *url* with any embedded credentials removed.

    The URL is parsed with :func:`urllib.parse.urlsplit` so that the
    ``username:password@`` component is stripped while the rest of the URL
    (scheme, host, port, path, query, fragment) is preserved.  This prevents
    credentials from ever being persisted or exported.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url
    # Rebuild netloc without userinfo
    netloc = parts.hostname or ""
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


#: Limitations attached to every result so the UI can display them.
DEFAULT_LIMITATIONS = [
    "This assessment is based on the structure of the URL and, where enabled, "
    "limited page-content signals. It cannot prove that a website is safe or "
    "unsafe.",
    "The model was trained on a historical dataset; phishing techniques evolve "
    "over time.",
    "A 'low risk' result is not a guarantee. Always verify the identity of a "
    "site before entering credentials or payment details.",
]


class ScanOutcome:
    """The result of a scan, ready to be persisted and serialised."""

    def __init__(
        self,
        *,
        scan_id: str,
        submitted_url: str,
        normalized_url: str,
        hostname: str,
        registrable_domain: str,
        status: str,
        analysis_coverage: str,
        classification: str,
        classification_label: str,
        guidance: str,
        risk_score: Optional[int],
        phishing_probability: Optional[float],
        indicators: List[Dict[str, Any]],
        explanation: Optional[Dict[str, Any]],
        warnings: List[str],
        model_version: Optional[str],
        model_algorithm: Optional[str],
        feature_schema_version: str,
        features: Optional[Dict[str, float]],
        threat_intel: Optional[Dict[str, Any]],
        page_analysis: Optional[Dict[str, Any]],
        error_code: Optional[str],
        error_message: Optional[str],
        duration_ms: int,
    ) -> None:
        self.scan_id = scan_id
        self.submitted_url = submitted_url
        self.normalized_url = normalized_url
        self.hostname = hostname
        self.registrable_domain = registrable_domain
        self.status = status
        self.analysis_coverage = analysis_coverage
        self.classification = classification
        self.classification_label = classification_label
        self.guidance = guidance
        self.risk_score = risk_score
        self.phishing_probability = phishing_probability
        self.indicators = indicators
        self.explanation = explanation
        self.warnings = warnings
        self.model_version = model_version
        self.model_algorithm = model_algorithm
        self.feature_schema_version = feature_schema_version
        self.features = features
        self.threat_intel = threat_intel
        self.page_analysis = page_analysis
        self.error_code = error_code
        self.error_message = error_message
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "submitted_url": self.submitted_url,
            "normalized_url": self.normalized_url,
            "hostname": self.hostname,
            "registrable_domain": self.registrable_domain,
            "status": self.status,
            "analysis_coverage": self.analysis_coverage,
            "classification": self.classification,
            "classification_label": self.classification_label,
            "guidance": self.guidance,
            "risk_score": self.risk_score,
            "phishing_probability": self.phishing_probability,
            "indicators": self.indicators,
            "explanation": self.explanation,
            "warnings": self.warnings,
            "model_version": self.model_version,
            "model_algorithm": self.model_algorithm,
            "feature_schema_version": self.feature_schema_version,
            "features": self.features,
            "threat_intelligence": self.threat_intel,
            "page_analysis": self.page_analysis,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "limitations": DEFAULT_LIMITATIONS,
        }


def _failed_outcome(
    *,
    submitted_url: str,
    normalized_url: str,
    hostname: str,
    registrable_domain: str,
    error_code: str,
    error_message: str,
    duration_ms: int,
    warnings: Optional[List[str]] = None,
) -> ScanOutcome:
    """Build a FAILED outcome (never a safe verdict)."""
    return ScanOutcome(
        scan_id=str(uuid.uuid4()),
        submitted_url=submitted_url,
        normalized_url=normalized_url,
        hostname=hostname,
        registrable_domain=registrable_domain,
        status=ScanStatus.FAILED,
        analysis_coverage="none",
        classification=UNKNOWN,
        classification_label="Analysis failed",
        guidance=(
            "The scan could not be completed, so no verdict can be given. Treat the "
            "link with caution and verify it manually."
        ),
        risk_score=None,
        phishing_probability=None,
        indicators=[],
        explanation=None,
        warnings=warnings or [],
        model_version=None,
        model_algorithm=None,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        features=None,
        threat_intel=None,
        page_analysis=None,
        error_code=error_code,
        error_message=error_message,
        duration_ms=duration_ms,
    )


def perform_scan(
    raw_url: str,
    db: Optional[Session] = None,
    include_page_analysis: bool = False,
    store_result: bool = True,
) -> ScanOutcome:
    """Run a complete website safety verification."""
    started = time.perf_counter()
    warnings: List[str] = []

    # -- 1. Validation --------------------------------------------------
    try:
        validated = validate_url(raw_url)
    except UrlValidationError as exc:
        duration = int((time.perf_counter() - started) * 1000)
        outcome = _failed_outcome(
            submitted_url=raw_url,
            normalized_url="",
            hostname="",
            registrable_domain="",
            error_code=exc.code,
            error_message=exc.message,
            duration_ms=duration,
        )
        if db is not None and store_result:
            _persist(db, outcome)
        return outcome

    if validated.scheme_inferred:
        warnings.append(
            "No scheme was supplied, so 'https://' was assumed for analysis. The "
            "submitted address was recorded unchanged."
        )

    # -- 2. Feature extraction ------------------------------------------
    try:
        features = extract_features(validated)
    except Exception as exc:  # noqa: BLE001
        duration = int((time.perf_counter() - started) * 1000)
        outcome = _failed_outcome(
            submitted_url=validated.original_input,
            normalized_url=validated.normalized_url,
            hostname=validated.hostname,
            registrable_domain=validated.registrable_domain,
            error_code="FEATURE_EXTRACTION_FAILED",
            error_message=str(exc),
            duration_ms=duration,
            warnings=warnings,
        )
        if db is not None and store_result:
            _persist(db, outcome)
        return outcome

    # -- 3. Model inference ---------------------------------------------
    if not model_service.is_loaded:
        model_service.load()

    try:
        prediction = model_service.predict(features)
    except ModelUnavailableError as exc:
        duration = int((time.perf_counter() - started) * 1000)
        outcome = _failed_outcome(
            submitted_url=validated.original_input,
            normalized_url=validated.normalized_url,
            hostname=validated.hostname,
            registrable_domain=validated.registrable_domain,
            error_code="MODEL_UNAVAILABLE",
            error_message=str(exc),
            duration_ms=duration,
            warnings=warnings,
        )
        if db is not None and store_result:
            _persist(db, outcome)
        return outcome

    # -- 4. Risk categorisation ------------------------------------------
    assessment = categorize(prediction.phishing_probability, prediction.thresholds)

    # -- 5. Explanation ---------------------------------------------------
    importance = model_service.feature_importance()
    explanation = explain_prediction(
        validated, features, prediction.phishing_probability, importance
    )
    indicators = explanation["evidence"]

    # -- 6. Threat intelligence (optional) --------------------------------
    threat_result = threat_intelligence.lookup(
        validated.normalized_url, validated.hostname
    )
    if threat_result.status == "unavailable":
        warnings.append(
            f"Threat intelligence lookup was unavailable "
            f"({threat_result.detail or 'no detail'}). "
            "This does not indicate that the site is safe."
        )
    elif threat_result.listed:
        # A confirmed match on a malicious-URL list escalates the verdict.
        if assessment.category == SAFE:
            assessment = categorize(
                max(prediction.phishing_probability, 0.99), prediction.thresholds
            )
        warnings.append(
            "The URL appears on a threat-intelligence feed of known malicious URLs."
        )
        indicators = list(indicators) + [
            {
                "category": "threat_intelligence_match",
                "value": 1,
                "description": threat_result.detail
                or "The URL is listed by an external threat-intelligence source.",
            }
        ]
        explanation = {
            **explanation,
            "evidence": indicators,
        }

    # -- 7. Optional page analysis ---------------------------------------
    page_analysis: Optional[Dict[str, Any]] = None
    analysis_coverage = "url_only"

    if include_page_analysis:
        if not settings.page_analysis_enabled:
            warnings.append(
                "Page-content analysis was requested but is disabled on this server "
                "(PAGE_ANALYSIS_ENABLED=false); only the URL was analysed."
            )
        else:
            page_analysis = _run_page_analysis(validated.normalized_url, warnings)

    if page_analysis is not None and page_analysis.get("fetched"):
        analysis_coverage = "url_and_page"
    elif include_page_analysis:
        analysis_coverage = "url_only"

    # -- 8. Persist --------------------------------------------------------
    duration = int((time.perf_counter() - started) * 1000)
    outcome = ScanOutcome(
        scan_id=str(uuid.uuid4()),
        submitted_url=_redact_userinfo(validated.original_input),
        normalized_url=validated.normalized_url,
        hostname=validated.hostname,
        registrable_domain=validated.registrable_domain,
        status=ScanStatus.COMPLETED,
        analysis_coverage=analysis_coverage,
        classification=assessment.category,
        classification_label=assessment.label,
        guidance=assessment.guidance,
        risk_score=assessment.risk_score,
        phishing_probability=round(prediction.phishing_probability, 6),
        indicators=indicators,
        explanation=explanation,
        warnings=warnings,
        model_version=prediction.model_version,
        model_algorithm=prediction.model_name,
        feature_schema_version=prediction.feature_schema_version,
        features=features,
        threat_intel=threat_result.as_dict(),
        page_analysis=page_analysis,
        error_code=None,
        error_message=None,
        duration_ms=duration,
    )

    if db is not None and store_result:
        _persist(db, outcome)

    return outcome


def _run_page_analysis(
    normalized_url: str, warnings: List[str]
) -> Optional[Dict[str, Any]]:
    """Run the optional page analysis, converting failures into warnings."""
    from backend.app.services.fetch import (
        FetchTimeoutError,
        FetchTooLargeError,
        SsrfBlockedError,
        analyze_page_content,
    )

    try:
        return analyze_page_content(normalized_url)
    except SsrfBlockedError as exc:
        warnings.append(f"Page analysis was blocked by the security policy: {exc}")
    except FetchTimeoutError as exc:
        warnings.append(f"Page analysis timed out: {exc}")
    except FetchTooLargeError as exc:
        warnings.append(f"Page analysis was abandoned: {exc}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Page analysis failed: %s", exc)
        warnings.append(f"Page analysis could not be completed: {exc}")
    return None


def _persist(db: Session, outcome: ScanOutcome) -> Scan:
    """Persist a scan outcome to the database."""
    record = Scan(
        id=outcome.scan_id,
        submitted_url=outcome.submitted_url,
        normalized_url=outcome.normalized_url,
        hostname=outcome.hostname or "",
        registrable_domain=outcome.registrable_domain or "",
        status=outcome.status,
        analysis_coverage=outcome.analysis_coverage,
        classification=outcome.classification,
        phishing_probability=outcome.phishing_probability,
        risk_score=outcome.risk_score,
        model_version=outcome.model_version,
        feature_schema_version=outcome.feature_schema_version,
        features=outcome.features,
        indicators={"evidence": outcome.indicators} if outcome.indicators else None,
        warnings=outcome.warnings or None,
        error_code=outcome.error_code,
        error_message=outcome.error_message,
        duration_ms=outcome.duration_ms,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
