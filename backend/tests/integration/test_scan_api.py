"""Integration tests for the scan submission endpoint.

These tests drive the real FastAPI application through the real trained model
and the real service layer.  Only the database is replaced (with an in-memory
SQLite database), so the whole request path - validation, feature extraction,
inference, risk categorisation, explanation and persistence - is exercised.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.scan import Classification, Scan, ScanStatus

SAFE_URL = "https://www.google.com/search?q=test"
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"


class TestScanSubmission:
    def test_a_safe_url_is_classified_as_safe(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": SAFE_URL})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        assert body["classification"] == "safe"
        assert body["risk_score"] < 50
        assert 0.0 <= body["phishing_probability"] <= 1.0

    def test_a_dangerous_url_is_classified_as_dangerous(
        self, client: TestClient
    ) -> None:
        response = client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        assert body["classification"] == "dangerous"
        assert body["risk_score"] > 80

    def test_the_dangerous_guidance_forbids_credentials_and_payment(
        self, client: TestClient
    ) -> None:
        response = client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        guidance = response.json()["guidance"].lower()
        assert "credential" in guidance
        assert "payment" in guidance

    def test_the_safe_guidance_does_not_claim_a_guarantee(
        self, client: TestClient
    ) -> None:
        response = client.post("/api/v1/scan", json={"url": SAFE_URL})
        guidance = response.json()["guidance"].lower()
        assert "not a guarantee" in guidance

    def test_the_response_reports_the_model_provenance(
        self, client: TestClient
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        assert body["model_version"]
        assert body["feature_schema_version"] == "1.0.0"
        assert body["model_algorithm"]

    def test_the_response_carries_evidence_and_contributions(
        self, client: TestClient
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": DANGEROUS_URL}).json()
        assert len(body["indicators"]) > 0
        explanation = body["explanation"]
        assert explanation is not None
        assert len(explanation["evidence"]) > 0
        assert explanation["note"]
        for row in explanation["top_contributing_features"]:
            assert row["feature"]
            assert row["contribution"] >= 0.0

    def test_the_response_lists_the_limitations(self, client: TestClient) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        assert len(body["limitations"]) >= 3

    def test_the_analysis_coverage_is_url_only_by_default(
        self, client: TestClient
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        assert body["analysis_coverage"] == "url_only"

    def test_the_submitted_url_is_echoed_verbatim(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": SAFE_URL})
        assert response.json()["submitted_url"] == SAFE_URL

    def test_whitespace_around_the_url_is_trimmed(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": f"  {SAFE_URL}  "})
        assert response.status_code == 200
        assert response.json()["submitted_url"] == SAFE_URL

    def test_a_url_without_a_scheme_is_accepted(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "www.google.com/search"})
        assert response.status_code == 200
        assert response.json()["normalized_url"].startswith("http")

    def test_a_scan_id_is_returned(self, client: TestClient) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        assert body["scan_id"]
        assert len(body["scan_id"]) == 36

    def test_the_duration_is_reported(self, client: TestClient) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        assert body["duration_ms"] is not None
        assert body["duration_ms"] >= 0


class TestScanPersistence:
    def test_a_scan_is_stored_in_the_database(
        self, client: TestClient, db_session: Session
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        stored = db_session.execute(
            select(Scan).where(Scan.id == body["scan_id"])
        ).scalars().first()
        assert stored is not None
        assert stored.submitted_url == SAFE_URL
        assert stored.classification == body["classification"]
        assert stored.model_version == body["model_version"]

    def test_store_result_false_keeps_the_history_empty(
        self, client: TestClient, db_session: Session
    ) -> None:
        response = client.post(
            "/api/v1/scan", json={"url": SAFE_URL, "store_result": False}
        )
        assert response.status_code == 200
        assert db_session.execute(select(Scan)).scalars().all() == []

    def test_the_stored_record_keeps_the_extracted_features(
        self, client: TestClient, db_session: Session
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        stored = db_session.execute(
            select(Scan).where(Scan.id == body["scan_id"])
        ).scalars().first()
        assert stored is not None
        assert stored.features
        assert len(stored.features) == 35

    def test_no_credentials_are_persisted(
        self, client: TestClient, db_session: Session
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        stored = db_session.execute(
            select(Scan).where(Scan.id == body["scan_id"])
        ).scalars().first()
        assert stored is not None
        dumped = repr(stored.__dict__)
        assert "password" not in dumped.lower()
        assert "cookie" not in dumped.lower()


class TestScanValidation:
    def test_an_empty_url_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": ""})
        assert response.status_code == 422

    def test_a_whitespace_only_url_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "   "})
        assert response.status_code == 422

    def test_a_missing_url_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={})
        assert response.status_code == 422

    def test_an_unsupported_scheme_produces_a_failed_scan(
        self, client: TestClient
    ) -> None:
        response = client.post("/api/v1/scan", json={"url": "ftp://example.com/file"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["classification"] == "unknown"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"
        assert body["error_message"]

    def test_a_non_http_scheme_is_never_classified(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["classification"] == "unknown"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"

    def test_a_file_scheme_is_never_classified(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "file:///etc/passwd"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["classification"] == "unknown"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"

    def test_an_overlong_url_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/scan", json={"url": "https://example.com/" + "a" * 5000}
        )
        assert response.status_code == 422

    def test_unknown_fields_are_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/scan", json={"url": SAFE_URL, "unexpected": "value"}
        )
        assert response.status_code == 422

    def test_a_failed_scan_is_stored_with_the_failed_status(
        self, client: TestClient, db_session: Session
    ) -> None:
        body = client.post("/api/v1/scan", json={"url": "ftp://example.com/file"}).json()
        stored = db_session.execute(
            select(Scan).where(Scan.id == body["scan_id"])
        ).scalars().first()
        assert stored is not None
        assert stored.status == ScanStatus.FAILED
        assert stored.classification == Classification.UNKNOWN
        assert stored.error_code == "UNSUPPORTED_SCHEME"

    def test_the_validation_error_body_is_uniform(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": ""})
        body = response.json()
        assert "detail" in body
        assert isinstance(body["detail"], list)
