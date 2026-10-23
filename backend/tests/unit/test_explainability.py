"""Unit tests for the explanation builder."""

from __future__ import annotations

import pytest

from phishguard.feature_extraction import extract_features, extract_features_from_url
from phishguard.feature_schema import FEATURE_NAMES
from phishguard.url_validation import validate_url
from backend.app.services.explainability import (
    build_indicators,
    explain_prediction,
    feature_importance_for_prediction,
)

SAFE_URL = "https://www.google.com/search?q=test"
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"


def _importance_rows(count: int = len(FEATURE_NAMES)):
    return [{"feature": name, "importance": 0.1} for name in FEATURE_NAMES[:count]]


class TestBuildIndicators:
    def test_builds_an_indicator_per_positive_feature(self) -> None:
        validated = validate_url(SAFE_URL)
        features = extract_features(validated)
        indicators = build_indicators(validated, features)
        assert len(indicators) > 0
        for indicator in indicators:
            assert indicator["value"] > 0
            assert indicator["description"]
            assert indicator["category"]

    def test_skips_features_with_zero_value(self) -> None:
        validated = validate_url(SAFE_URL)
        # ``uses_https`` is the only feature whose *absence* is itself an
        # indicator, so it is set to 1 here to isolate the "skip zeros" rule.
        zero_features = {name: 0.0 for name in FEATURE_NAMES}
        zero_features["uses_https"] = 1.0
        indicators = build_indicators(validated, zero_features)
        assert indicators == []

    def test_reports_the_ip_address_indicator_for_ip_hosts(self) -> None:
        validated = validate_url("http://192.168.0.1/login")
        features = extract_features(validated)
        categories = [row["category"] for row in build_indicators(validated, features)]
        assert "ip_address_host" in categories

    def test_reports_the_brand_impersonation_indicator(self) -> None:
        # A recognised brand token on a domain that is not the brand's own.
        validated = validate_url("http://paypal.secure-login.example/account/verify")
        features = extract_features(validated)
        categories = [row["category"] for row in build_indicators(validated, features)]
        assert "brand_impersonation" in categories

    def test_reports_the_non_https_indicator(self) -> None:
        validated = validate_url("http://example.com/login")
        features = extract_features(validated)
        categories = [row["category"] for row in build_indicators(validated, features)]
        assert "non_https_scheme" in categories


class TestFeatureImportanceForPrediction:
    def test_returns_at_most_ten_contributing_features(self) -> None:
        features = extract_features_from_url(DANGEROUS_URL)
        contributing = feature_importance_for_prediction(features, _importance_rows())
        assert len(contributing) <= 10

    def test_sorts_by_contribution_descending(self) -> None:
        features = extract_features_from_url(DANGEROUS_URL)
        contributing = feature_importance_for_prediction(features, _importance_rows())
        contributions = [row["contribution"] for row in contributing]
        assert contributions == sorted(contributions, reverse=True)

    def test_excludes_zero_valued_features(self) -> None:
        features = extract_features_from_url(SAFE_URL)
        contributing = feature_importance_for_prediction(features, _importance_rows())
        assert all(row["value"] != 0.0 for row in contributing)

    def test_handles_empty_importance(self) -> None:
        features = extract_features_from_url(SAFE_URL)
        assert feature_importance_for_prediction(features, []) == []

    def test_contribution_is_value_times_global_importance(self) -> None:
        features = extract_features_from_url(DANGEROUS_URL)
        importance = [{"feature": name, "importance": 0.5} for name in FEATURE_NAMES]
        contributing = feature_importance_for_prediction(features, importance)
        for row in contributing:
            assert row["contribution"] == pytest.approx(row["value"] * 0.5)
            assert row["global_importance"] == pytest.approx(0.5)


class TestExplainPrediction:
    def test_assembles_evidence_and_contributions(self) -> None:
        validated = validate_url(DANGEROUS_URL)
        features = extract_features(validated)
        explanation = explain_prediction(validated, features, 0.97, _importance_rows())
        assert set(explanation) == {"evidence", "top_contributing_features", "note"}
        assert explanation["note"]
        assert len(explanation["evidence"]) > 0
        assert len(explanation["top_contributing_features"]) <= 10

    def test_uses_the_provided_probability(self) -> None:
        validated = validate_url(SAFE_URL)
        features = extract_features(validated)
        explanation = explain_prediction(validated, features, 0.3, [])
        assert explanation["top_contributing_features"] == []

    def test_the_note_disclaims_causality(self) -> None:
        validated = validate_url(DANGEROUS_URL)
        features = extract_features(validated)
        explanation = explain_prediction(validated, features, 0.97, _importance_rows())
        note = explanation["note"].lower()
        assert "correlation" in note or "causal" in note or "association" in note
