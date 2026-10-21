"""
Risk scoring and the SAFE / SUSPICIOUS / DANGEROUS decision policy.

The underlying model is a **binary** classifier (phishing = 1).  The three
user-facing categories are produced by applying two probability thresholds
that were selected on the validation partition during training:

    probability <  suspicious_threshold          -> SAFE
    suspicious_threshold <= probability
                        <  dangerous_threshold    -> SUSPICIOUS
    probability >= dangerous_threshold           -> DANGEROUS

This policy is documented in ``docs/model_card.md``.  The system never
implies that the model was trained as a three-class classifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

#: Canonical category names used across the API, database and UI.
SAFE = "safe"
SUSPICIOUS = "suspicious"
DANGEROUS = "dangerous"
INCONCLUSIVE = "inconclusive"
UNKNOWN = "unknown"

#: Human-readable labels shown in the interface.
CATEGORY_LABELS: Dict[str, str] = {
    SAFE: "Low risk - no strong phishing indicators detected",
    SUSPICIOUS: "Suspicious - review required before proceeding",
    DANGEROUS: "Likely phishing - do not enter credentials or payment details",
    INCONCLUSIVE: "Inconclusive - insufficient evidence to judge this URL",
    UNKNOWN: "Not analysed",
}

#: Short guidance shown next to each verdict.
CATEGORY_GUIDANCE: Dict[str, str] = {
    SAFE: (
        "No strong phishing indicators were found in the URL. This is not a guarantee "
        "that the site is harmless - continue to check who the site claims to be before "
        "signing in or entering personal details."
    ),
    SUSPICIOUS: (
        "Some indicators associated with phishing were found. Verify the address "
        "independently (for example by navigating to the organisation's site from a "
        "bookmark or by phone) before entering any personal information."
    ),
    DANGEROUS: (
        "Do not enter credentials, payment details or personal information on this site. "
        "Close the page and reach the organisation through its official website."
    ),
    INCONCLUSIVE: (
        "The URL could not be analysed completely, so no verdict can be given. Treat "
        "the link with caution and verify it manually."
    ),
    UNKNOWN: "The URL was not analysed.",
}


@dataclass
class RiskAssessment:
    """The outcome of applying the decision policy to a probability."""

    category: str
    label: str
    guidance: str
    risk_score: int
    probability: float
    thresholds: Dict[str, float]

    def as_dict(self) -> Dict[str, object]:
        return {
            "category": self.category,
            "label": self.label,
            "guidance": self.guidance,
            "risk_score": self.risk_score,
            "phishing_probability": self.probability,
            "thresholds": self.thresholds,
        }


def risk_score_from_probability(probability: float) -> int:
    """Convert a calibrated probability into a 0-100 operational risk score.

    The score is a monotone rescaling of the calibrated probability.  It is a
    *relative indicator*, not a probability of harm, and the UI labels it as
    such.
    """
    bounded = max(0.0, min(1.0, float(probability)))
    return int(round(bounded * 100))


def categorize(
    probability: float,
    thresholds: Optional[Dict[str, float]] = None,
) -> RiskAssessment:
    """Apply the documented threshold policy to a calibrated probability."""
    thresholds = thresholds or {}
    suspicious_threshold = float(thresholds.get("suspicious_threshold", 0.5))
    dangerous_threshold = float(thresholds.get("dangerous_threshold", 0.9))

    # Guard against an inverted policy (dangerous must not be below suspicious).
    if dangerous_threshold < suspicious_threshold:
        dangerous_threshold = suspicious_threshold

    if probability >= dangerous_threshold:
        category = DANGEROUS
    elif probability >= suspicious_threshold:
        category = SUSPICIOUS
    else:
        category = SAFE

    return RiskAssessment(
        category=category,
        label=CATEGORY_LABELS[category],
        guidance=CATEGORY_GUIDANCE[category],
        risk_score=risk_score_from_probability(probability),
        probability=float(probability),
        thresholds={
            "suspicious_threshold": suspicious_threshold,
            "dangerous_threshold": dangerous_threshold,
        },
    )


def inconclusive_assessment(reason: str) -> RiskAssessment:
    """Build the INCONCLUSIVE outcome used when evidence is insufficient."""
    return RiskAssessment(
        category=INCONCLUSIVE,
        label=CATEGORY_LABELS[INCONCLUSIVE],
        guidance=f"{CATEGORY_GUIDANCE[INCONCLUSIVE]} ({reason})",
        risk_score=0,
        probability=0.0,
        thresholds={},
    )
