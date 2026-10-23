"""Unit tests for the model loader and predictor.

The tests exercise the **real** trained artifact that the API serves, so a
regression in the artifact (wrong feature schema, corrupt file, missing
thresholds) fails here instead of silently degrading the product.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator

import pytest

from backend.app.core.config import settings
from backend.app.services.classifier import (
    ModelUnavailableError,
    model_service,
)
from phishguard.feature_extraction import extract_features, extract_features_from_url
from phishguard.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from phishguard.url_validation import validate_url

SAFE_URL = "https://www.google.com/search?q=test"
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"

_ORIGINAL_MODEL_PATH = model_service.model_path


@pytest.fixture(autouse=True)
def restore_model() -> Iterator[None]:
    """Re-load the real artifact after every test in this module.

    Several tests deliberately break the model path; leaving the shared
    service unloaded would leak into unrelated test modules.
    """
    yield
    model_service.model_path = _ORIGINAL_MODEL_PATH
    model_service.load(force=True)


def _load_artifact() -> Dict[str, Any]:
    """Load the real artifact from disk into a plain dict."""
    import joblib

    return joblib.load(settings.model_path)


class TestLifecycle:
    def test_load_succeeds_with_the_real_artifact(self) -> None:
        assert model_service.load(force=True), (
            f"Could not load the real artifact: {model_service.load_error!r}"
        )
        assert model_service.is_loaded
        info = model_service.info()
        assert info["available"] is True
        assert info["algorithm"]
        assert info["feature_count"] == len(FEATURE_NAMES)

    def test_load_is_idempotent(self) -> None:
        first = model_service.load(force=False)
        second = model_service.load(force=False)
        assert first is True
        assert second is True

    def test_load_reports_a_missing_file(self, tmp_path: str) -> None:
        fake_path = str(tmp_path / "does_not_exist.joblib")
        model_service.model_path = fake_path
        assert model_service.load(force=True) is False
        assert model_service.load_error
        assert "not found" in model_service.load_error.lower()

    def test_a_failed_load_leaves_the_service_unloaded(self, tmp_path: str) -> None:
        model_service.model_path = str(tmp_path / "does_not_exist.joblib")
        model_service.load(force=True)
        assert model_service.is_loaded is False

    def test_load_rejects_an_malformed_artifact(self, tmp_path: str) -> None:
        import joblib

        bad = tmp_path / "bad.joblib"
        joblib.dump({"not": "a model"}, bad)
        model_service.model_path = str(bad)
        assert model_service.load(force=True) is False
        assert "unexpected structure" in model_service.load_error

    def test_load_rejects_a_schema_mismatch(self, tmp_path: str) -> None:
        import joblib

        bad = tmp_path / "bad_schema.joblib"
        artifact = _load_artifact()
        artifact["feature_schema_version"] = "9.9.9"
        joblib.dump(artifact, bad)
        model_service.model_path = str(bad)
        assert model_service.load(force=True) is False
        assert "Feature schema mismatch" in model_service.load_error

    def test_load_rejects_a_feature_list_mismatch(self, tmp_path: str) -> None:
        import joblib

        bad = tmp_path / "bad_features.joblib"
        artifact = _load_artifact()
        artifact["feature_names"] = list(FEATURE_NAMES)[:10]
        joblib.dump(artifact, bad)
        model_service.model_path = str(bad)
        assert model_service.load(force=True) is False
        assert "Feature schema mismatch" in model_service.load_error


class TestPrediction:
    def test_predict_returns_a_probability_in_unit_range(self) -> None:
        probability = model_service.predict(
            extract_features_from_url(SAFE_URL)
        ).phishing_probability
        assert 0.0 <= probability <= 1.0

    def test_predict_on_a_safe_url_scores_low(self) -> None:
        probability = model_service.predict(
            extract_features_from_url(SAFE_URL)
        ).phishing_probability
        assert probability < 0.5

    def test_predict_on_a_dangerous_url_scores_high(self) -> None:
        probability = model_service.predict(
            extract_features_from_url(DANGEROUS_URL)
        ).phishing_probability
        assert probability > 0.8

    def test_predict_requires_all_features(self) -> None:
        features = extract_features_from_url(SAFE_URL)
        missing = {name for name in FEATURE_NAMES if name not in features}
        with pytest.raises(ModelUnavailableError):
            model_service.predict({name: 0.0 for name in missing})

    def test_predict_requires_the_model_to_be_loaded(self, tmp_path: str) -> None:
        model_service.model_path = str(tmp_path / "missing.joblib")
        model_service.load(force=True)
        with pytest.raises(ModelUnavailableError):
            model_service.predict(extract_features_from_url(SAFE_URL))

    def test_predict_returns_metadata(self) -> None:
        prediction = model_service.predict(
            extract_features_from_url(DANGEROUS_URL)
        )
        assert prediction.model_version
        assert prediction.feature_schema_version == FEATURE_SCHEMA_VERSION
        assert prediction.model_name
        assert prediction.thresholds
        assert prediction.inference_ms >= 0.0

    def test_prediction_uses_the_trained_thresholds(self) -> None:
        prediction = model_service.predict(extract_features_from_url(SAFE_URL))
        assert prediction.thresholds["suspicious_threshold"] == 0.625
        assert prediction.thresholds["dangerous_threshold"] == 0.895

    def test_binary_label_follows_the_suspicious_threshold(self) -> None:
        safe = model_service.predict(extract_features_from_url(SAFE_URL))
        dangerous = model_service.predict(extract_features_from_url(DANGEROUS_URL))
        assert safe.binary_label == 0
        assert dangerous.binary_label == 1


class TestInfo:
    def test_info_reports_the_loaded_model(self) -> None:
        info = model_service.info()
        assert info["available"] is True
        assert info["model_version"]
        assert info["thresholds"]
        assert info["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        assert list(info["supported_features"]) == list(FEATURE_NAMES)

    def test_info_reports_unavailable_when_not_loaded(self, tmp_path: str) -> None:
        model_service.model_path = str(tmp_path / "missing.joblib")
        model_service.load(force=True)
        info = model_service.info()
        assert info["available"] is False
        assert info["error"]

    def test_feature_importance_reads_metrics_when_present(self) -> None:
        importances = model_service.feature_importance()
        # The training run recorded feature importance; it must be non-empty.
        assert isinstance(importances, list)
        assert importances, "model_metrics.json must contain global feature importance"
        for row in importances:
            assert row["feature"] in FEATURE_NAMES
            assert row["importance"] >= 0.0
        assert importances == sorted(
            importances, key=lambda row: row["importance"], reverse=True
        )

    def test_feature_importance_returns_empty_when_metrics_absent(
        self, tmp_path: str
    ) -> None:
        model_service.model_path = str(tmp_path / "missing.joblib")
        assert model_service.feature_importance() == []


class TestPredictionConsistency:
    """The same URL must always produce the same probability."""

    def test_repeated_predictions_are_stable(self) -> None:
        features = extract_features_from_url(SAFE_URL)
        first = model_service.predict(features).phishing_probability
        second = model_service.predict(features).phishing_probability
        assert first == second

    def test_validate_then_predict_matches_raw_predict(self) -> None:
        validated = validate_url(SAFE_URL)
        features = extract_features(validated)
        raw = model_service.predict(features)
        direct = model_service.predict(extract_features_from_url(SAFE_URL))
        assert raw.phishing_probability == direct.phishing_probability
