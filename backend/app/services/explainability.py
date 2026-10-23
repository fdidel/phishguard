"""
Explainability for individual predictions.  The explanations are derived from
the *evidence actually extracted* for the scanned URL - they are not invented.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from phishguard.feature_schema import (
    BRAND_OFFICIAL_DOMAINS,
    FEATURE_NAMES,
    RISKY_TLDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
)
from phishguard.url_validation import ValidatedUrl

#: Evidence categories that map to human-readable indicators.
INDICATOR_CATEGORIES = [
    "unusually_long_url",
    "ip_address_host",
    "at_symbol_userinfo",
    "suspicious_keyword",
    "brand_impersonation",
    "known_shortener",
    "risky_tld",
    "suspicious_hyphen_pattern",
    "high_special_char_ratio",
    "high_digit_ratio",
    "double_slash_redirect",
    "path_depth",
    "percent_encoding",
    "punycode_hostname",
]


def build_indicators(
    validated: ValidatedUrl,
    features: Dict[str, float],
) -> List[Dict[str, object]]:
    """Return the evidence indicators that contributed to a prediction.

    Each indicator is a small dict with ``category``, ``value`` and a short
    ``description``.  Only features whose value is non-zero (or whose value
    exceeds a small threshold) are reported as evidence; features that are
    normal for legitimate URLs are omitted so the explanation stays concise.
    """
    indicators: List[Dict[str, object]] = []

    def add(category: str, value: float, description: str) -> None:
        if value > 0:
            indicators.append(
                {
                    "category": category,
                    "value": round(float(value), 4),
                    "description": description,
                }
            )

    add(
        "unusually_long_url",
        features.get("url_length", 0.0),
        f"URL length is {int(features.get('url_length', 0))} characters."
        + (" This is unusually long for a typical web address." if features.get("url_length", 0) > 150 else ""),
    )

    if int(features.get("has_ip_address", 0)) == 1:
        indicators.append(
            {
                "category": "ip_address_host",
                "value": 1,
                "description": "The hostname is an IP address literal, which is uncommon for a legitimate website.",
            }
        )

    if int(features.get("has_at_symbol", 0)) == 1:
        indicators.append(
            {
                "category": "at_symbol_userinfo",
                "value": 1,
                "description": "The URL embeds user information or an '@' symbol, which can hide the real host.",
            }
        )

    kw_count = int(features.get("suspicious_keyword_count", 0))
    if kw_count > 0:
        keywords = [k for k in SUSPICIOUS_KEYWORDS if k in validated.normalized_url.lower()]
        indicators.append(
            {
                "category": "suspicious_keyword",
                "value": kw_count,
                "description": (
                    f"{kw_count} phishing-intent keyword(s) were found in the URL: "
                    + ", ".join(keywords[:8])
                    + (" ..." if len(keywords) > 8 else "")
                    + "."
                ),
            }
        )

    brand_mismatch = int(features.get("brand_mismatch_count", 0))
    if brand_mismatch > 0:
        indicators.append(
            {
                "category": "brand_impersonation",
                "value": brand_mismatch,
                "description": (
                    f"{brand_mismatch} recognised brand token(s) appear in the URL but the "
                    f"registrable domain does not match their official domain."
                ),
            }
        )

    if int(features.get("known_shortener", 0)) == 1:
        indicators.append(
            {
                "category": "known_shortener",
                "value": 1,
                "description": "The hostname belongs to a known URL shortening service, which is often used to obscure the real destination.",
            }
        )

    if int(features.get("risky_tld", 0)) == 1:
        indicators.append(
            {
                "category": "risky_tld",
                "value": 1,
                "description": "The public suffix is one of the risky TLDs commonly used for bulk malicious registrations.",
            }
        )

    if int(features.get("has_double_slash_in_path", 0)) == 1:
        indicators.append(
            {
                "category": "double_slash_redirect",
                "value": 1,
                "description": "The path contains '//', a common redirect-style artefact.",
            }
        )

    if int(features.get("has_port", 0)) == 1:
        indicators.append(
            {
                "category": "explicit_port",
                "value": 1,
                "description": "An explicit TCP port is present in the URL.",
            }
        )

    if int(features.get("uses_https", 0)) == 0:
        indicators.append(
            {
                "category": "non_https_scheme",
                "value": 1,
                "description": "The URL uses http rather than https, which is less common for sensitive sites.",
            }
        )

    return indicators


def feature_importance_for_prediction(
    features: Dict[str, float], importance: List[Dict[str, object]]
) -> List[Dict[str, object]]:
    """Return the top contributing features for this single prediction.

    This is a *local* view of global feature importance: it ranks the features
    by how strongly they push the model towards the predicted class, using the
    calibrated probability as the signal.  It is explicitly labelled as a
    contribution estimate, not a causal attribution.
    """
    if not importance:
        return []

    importance_map = {row["feature"]: row["importance"] for row in importance}
    contributing = []
    for name in FEATURE_NAMES:
        value = features.get(name, 0.0)
        imp = importance_map.get(name, 0.0)
        if value != 0 and imp > 0:
            # The reported value is rounded first so that a client can
            # reproduce the contribution as ``value * global_importance``.
            rounded_value = round(float(value), 4)
            rounded_importance = round(float(imp), 6)
            contributing.append(
                {
                    "feature": name,
                    "value": rounded_value,
                    "global_importance": rounded_importance,
                    "contribution": round(rounded_value * rounded_importance, 6),
                }
            )
    contributing.sort(key=lambda row: row["contribution"], reverse=True)
    return contributing[:10]


def explain_prediction(
    validated: ValidatedUrl,
    features: Dict[str, float],
    probability: float,
    importance: List[Dict[str, object]],
) -> Dict[str, object]:
    """Assemble a complete, truthful explanation for a single prediction."""
    indicators = build_indicators(validated, features)
    contributing = feature_importance_for_prediction(features, importance)

    return {
        "evidence": indicators,
        "top_contributing_features": contributing,
        "note": (
            "These explanations describe the evidence extracted from the URL and the "
            "model's contribution estimates. They do not prove causality."
        ),
    }
