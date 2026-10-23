"""Integration tests for the system endpoints.

Covers ``GET /health``, ``GET /api/v1/model/info``,
``GET /api/v1/model/metrics`` and ``POST /api/v1/feedback``.

These tests are the guard-rail against the API ever reporting *fabricated*
model metrics: the values served by ``/model/metrics`` are read back from the
saved training-run artifact and must match it exactly.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.core.config import settings

SAFE_URL = "https://www.google.com/search?q=test"


def _metrics_file() -> dict:
    """Load the saved training-run metrics straight from disk."""
    path = Path(settings.metrics_path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class TestHealth:
    def test_the_service_reports_healthy(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] == "ok"

    def test_the_health_probe_reports_the_model_state(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert body["model_loaded"] is True
        assert body["model_version"]

    def test_the_health_probe_reports_the_feature_flags(
        self, client: TestClient
    ) -> None:
        body = client.get("/health").json()
        assert isinstance(body["page_analysis_enabled"], bool)
        assert isinstance(body["threat_intel_enabled"], bool)
        assert body["timestamp"]


class TestModelInfo:
    def test_the_model_is_reported_as_available(self, client: TestClient) -> None:
        response = client.get("/api/v1/model/info")
        assert response.status_code == 200
        body = response.json()
        assert body["available"] is True
        assert body["error"] is None

    def test_the_model_metadata_is_complete(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/info").json()
        assert body["model_version"]
        assert body["feature_schema_version"] == "1.0.0"
        assert body["algorithm"]
        assert body["trained_at"]
        assert body["random_seed"] is not None

    def test_the_supported_features_match_the_schema(
        self, client: TestClient
    ) -> None:
        body = client.get("/api/v1/model/info").json()
        assert body["feature_count"] == 35
        assert len(body["supported_features"]) == 35

    def test_the_thresholds_are_reported(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/info").json()
        assert body["thresholds"]["suspicious_threshold"] == 0.625
        assert body["thresholds"]["dangerous_threshold"] == 0.895


class TestModelMetrics:
    def test_the_metrics_endpoint_serves_the_saved_training_run(
        self, client: TestClient
    ) -> None:
        response = client.get("/api/v1/model/metrics")
        assert response.status_code == 200
        body = response.json()
        saved = _metrics_file()
        assert body["model_version"] == saved["model_version"]
        assert body["selected_model"] == saved["selected_model"]
        assert body["random_seed"] == saved["random_seed"]

    def test_the_reported_metrics_match_the_saved_artifact(
        self, client: TestClient
    ) -> None:
        body = client.get("/api/v1/model/metrics").json()
        saved = _metrics_file()
        assert body["test_set"]["metrics"] == saved["test_set"]["metrics"]
        assert body["test_set"]["error_rates"] == saved["test_set"]["error_rates"]

    def test_the_held_out_test_metrics_are_reported(
        self, client: TestClient
    ) -> None:
        body = client.get("/api/v1/model/metrics").json()
        metrics = body["test_set"]["metrics"]
        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert 0.0 <= metrics["precision"] <= 1.0
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["f1"] <= 1.0

    def test_the_confusion_matrix_is_reported(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/metrics").json()
        matrix = body["test_set"]["confusion_matrix"]
        assert len(matrix["matrix"]) == 2
        assert matrix["total"] > 0
        assert matrix["true_positives"] > 0
        assert matrix["true_negatives"] > 0

    def test_the_model_comparison_is_reported(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/metrics").json()
        comparison = body["model_comparison"]
        assert len(comparison) >= 5
        names = {row.get("model") or row.get("name") for row in comparison}
        assert len(names) >= 5

    def test_the_feature_importance_is_not_empty(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/metrics").json()
        importance = body["feature_importance"]
        assert len(importance) == 35
        assert all(row["feature"] for row in importance)
        assert all(row["importance"] >= 0 for row in importance)

    def test_the_inference_latency_is_reported(self, client: TestClient) -> None:
        body = client.get("/api/v1/model/metrics").json()
        latency = body["inference_latency"]
        assert latency
        assert any("ms" in str(key).lower() for key in latency)


class TestFeedback:
    def test_feedback_is_recorded(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": submitted["scan_id"],
                "is_correct": True,
                "correct_classification": "safe",
                "comment": "Looks fine to me.",
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["feedback_id"]
        assert body["scan_id"] == submitted["scan_id"]
        assert body["recorded_at"]

    def test_feedback_without_a_classification_is_accepted(
        self, client: TestClient
    ) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.post(
            "/api/v1/feedback",
            json={"scan_id": submitted["scan_id"], "is_correct": False},
        )
        assert response.status_code == 201

    def test_feedback_for_an_unknown_scan_returns_404(
        self, client: TestClient
    ) -> None:
        response = client.post(
            "/api/v1/feedback",
            json={"scan_id": "does-not-exist", "is_correct": True},
        )
        assert response.status_code == 404

    def test_feedback_without_a_scan_id_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/v1/feedback", json={"is_correct": True})
        assert response.status_code == 422

    def test_an_invalid_correct_classification_is_rejected(
        self, client: TestClient
    ) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": submitted["scan_id"],
                "is_correct": False,
                "correct_classification": "bogus",
            },
        )
        assert response.status_code == 422

    def test_an_overlong_comment_is_rejected(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": submitted["scan_id"],
                "is_correct": True,
                "comment": "x" * 5000,
            },
        )
        assert response.status_code == 422

    def test_unknown_fields_are_rejected(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": submitted["scan_id"],
                "is_correct": True,
                "unexpected": "value",
            },
        )
        assert response.status_code == 422


class TestOpenApi:
    def test_the_openapi_document_lists_every_public_endpoint(
        self, client: TestClient
    ) -> None:
        paths = client.get("/openapi.json").json()["paths"]
        assert "/health" in paths
        assert "/api/v1/scan" in paths
        assert "/api/v1/scans" in paths
        assert "/api/v1/scans/{scan_id}" in paths
        assert "/api/v1/model/info" in paths
        assert "/api/v1/model/metrics" in paths
        assert "/api/v1/feedback" in paths
        assert "/api/v1/reports/summary" in paths
        assert "/api/v1/reports/export.csv" in paths
