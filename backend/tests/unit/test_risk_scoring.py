"""Unit tests for the decision policy that maps probabilities to verdicts."""

from __future__ import annotations

import json

import pytest

from backend.app.core.config import settings
from backend.app.services.risk_scoring import (
    CATEGORY_GUIDANCE,
    CATEGORY_LABELS,
    DANGEROUS,
    INCONCLUSIVE,
    SAFE,
    SUSPICIOUS,
    UNKNOWN,
    RiskAssessment,
    categorize,
    inconclusive_assessment,
    risk_score_from_probability,
)


class TestRiskScore:
    def test_zero_probability_maps_to_score_zero(self) -> None:
        assert risk_score_from_probability(0.0) == 0

    def test_one_probability_maps_to_score_hundred(self) -> None:
        assert risk_score_from_probability(1.0) == 100

    def test_midpoint_maps_to_the_nearest_integer(self) -> None:
        assert risk_score_from_probability(0.5) == 50

    def test_values_outside_unit_interval_are_clamped(self) -> None:
        assert risk_score_from_probability(-0.2) == 0
        assert risk_score_from_probability(1.5) == 100


class TestCategorize:
    def test_below_suspicious_threshold_is_safe(self) -> None:
        assessment = categorize(0.3)
        assert assessment.category == SAFE
        assert assessment.label == CATEGORY_LABELS[SAFE]
        assert assessment.risk_score == 30

    def test_at_or_above_dangerous_threshold_is_dangerous(self) -> None:
        assessment = categorize(0.95)
        assert assessment.category == DANGEROUS
        assert assessment.label == CATEGORY_LABELS[DANGEROUS]
        assert assessment.risk_score == 95

    def test_between_thresholds_is_suspicious(self) -> None:
        assessment = categorize(0.7)
        assert assessment.category == SUSPICIOUS
        assert assessment.label == CATEGORY_LABELS[SUSPICIOUS]

    def test_the_threshold_boundaries_are_inclusive(self) -> None:
        thresholds = {"suspicious_threshold": 0.5, "dangerous_threshold": 0.9}
        assert categorize(0.5, thresholds=thresholds).category == SUSPICIOUS
        assert categorize(0.9, thresholds=thresholds).category == DANGEROUS
        assert categorize(0.49, thresholds=thresholds).category == SAFE

    def test_custom_thresholds_override_defaults(self) -> None:
        assessment = categorize(
            0.6, thresholds={"suspicious_threshold": 0.4, "dangerous_threshold": 0.8}
        )
        assert assessment.category == SUSPICIOUS

    def test_inverted_thresholds_are_corrected(self) -> None:
        assessment = categorize(
            0.95, thresholds={"dangerous_threshold": 0.5, "suspicious_threshold": 0.8}
        )
        # The dangerous threshold is forced up to the suspicious one.
        assert assessment.category == DANGEROUS

    def test_the_assessment_reports_the_thresholds_used(self) -> None:
        assessment = categorize(
            0.7, thresholds={"suspicious_threshold": 0.6, "dangerous_threshold": 0.9}
        )
        assert assessment.thresholds["suspicious_threshold"] == 0.6
        assert assessment.thresholds["dangerous_threshold"] == 0.9

    def test_as_dict_exposes_the_probability(self) -> None:
        assessment = categorize(0.7)
        payload = assessment.as_dict()
        assert payload["category"] == assessment.category
        assert payload["risk_score"] == assessment.risk_score
        assert payload["phishing_probability"] == pytest.approx(assessment.probability)
        assert payload["label"] == assessment.label
        assert payload["guidance"] == assessment.guidance

    def test_as_dict_roundtrips_into_the_dataclass(self) -> None:
        assessment = categorize(0.7)
        restored = RiskAssessment(
            category=assessment.category,
            label=assessment.label,
            guidance=assessment.guidance,
            risk_score=assessment.risk_score,
            probability=assessment.probability,
            thresholds=assessment.thresholds,
        )
        assert restored.as_dict() == assessment.as_dict()


class TestInconclusive:
    def test_inconclusive_has_zero_score(self) -> None:
        assessment = inconclusive_assessment("no evidence")
        assert assessment.category == INCONCLUSIVE
        assert assessment.risk_score == 0
        assert assessment.probability == 0.0

    def test_inconclusive_carries_the_reason(self) -> None:
        assessment = inconclusive_assessment("insufficient data")
        assert "insufficient data" in assessment.guidance

    def test_inconclusive_is_never_reported_as_safe(self) -> None:
        assert inconclusive_assessment("anything").category != SAFE
        assert inconclusive_assessment("anything").category != DANGEROUS


class TestCategoryText:
    """Every category must carry a distinct label and non-empty guidance."""

    CATEGORIES = (SAFE, SUSPICIOUS, DANGEROUS, INCONCLUSIVE, UNKNOWN)

    def test_every_category_has_a_label_and_guidance(self) -> None:
        for category in self.CATEGORIES:
            assert CATEGORY_LABELS[category]
            assert CATEGORY_GUIDANCE[category]

    def test_the_labels_are_distinct(self) -> None:
        labels = [CATEGORY_LABELS[category] for category in self.CATEGORIES]
        assert len(set(labels)) == len(labels)

    def test_the_dangerous_guidance_forbids_credentials_and_payment(self) -> None:
        guidance = CATEGORY_GUIDANCE[DANGEROUS].lower()
        assert "credential" in guidance
        assert "payment" in guidance

    def test_the_safe_guidance_does_not_claim_a_guarantee(self) -> None:
        guidance = CATEGORY_GUIDANCE[SAFE].lower()
        assert "guarantee" in guidance
        assert "not a guarantee" in guidance

    def test_the_inconclusive_guidance_explains_that_no_verdict_is_possible(
        self,
    ) -> None:
        guidance = CATEGORY_GUIDANCE[INCONCLUSIVE].lower()
        assert "no verdict" in guidance


class TestThresholdPolicy:
    """The documented policy must hold on the trained model's thresholds."""

    def test_dangerous_threshold_is_high(self) -> None:
        with open(settings.metrics_path, encoding="utf-8") as handle:
            metrics = json.load(handle)
        thresholds = metrics["thresholds"]
        assert thresholds["dangerous_threshold"] > thresholds["suspicious_threshold"]
        assert thresholds["dangerous_max_fpr_constraint"] < 0.05

    def test_the_trained_thresholds_match_the_policy_defaults(self) -> None:
        with open(settings.metrics_path, encoding="utf-8") as handle:
            metrics = json.load(handle)
        thresholds = metrics["thresholds"]
        assessment = categorize(
            (thresholds["suspicious_threshold"] + thresholds["dangerous_threshold"]) / 2,
            thresholds=thresholds,
        )
        assert assessment.category == SUSPICIOUS
