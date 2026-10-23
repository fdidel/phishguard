"""Integration tests for the reporting endpoints.

Covers ``GET /api/v1/reports/summary`` and ``GET /api/v1/reports/export.csv``.
"""

from __future__ import annotations

import csv
import io

from fastapi.testclient import TestClient

SAFE_URL = "https://www.google.com/search?q=test"
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"
OTHER_SAFE_URL = "https://en.wikipedia.org/wiki/Phishing"


class TestReportSummary:
    def test_an_empty_history_summarises_to_zeroes(self, client: TestClient) -> None:
        response = client.get("/api/v1/reports/summary")
        assert response.status_code == 200
        body = response.json()
        assert body["total_scans"] == 0
        assert body["by_status"] == {}
        assert body["by_classification"] == {}
        assert body["average_risk_score"] is None
        assert body["dangerous_scans"] == 0
        assert body["unique_domains"] == 0
        assert body["generated_at"]

    def test_the_summary_counts_the_scans(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/reports/summary").json()
        assert body["total_scans"] == 2
        assert body["by_status"]["completed"] == 2
        assert body["safe_scans"] + body["dangerous_scans"] + body[
            "suspicious_scans"
        ] == 2

    def test_the_summary_counts_failed_scans(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": "ftp://example.com/file"})
        body = client.get("/api/v1/reports/summary").json()
        assert body["total_scans"] == 1
        assert body["failed_scans"] == 1
        assert body["by_status"]["failed"] == 1
        assert body["by_classification"]["unknown"] == 1

    def test_the_summary_reports_the_average_risk_score(
        self, client: TestClient
    ) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/reports/summary").json()
        assert body["average_risk_score"] is not None
        assert 0 <= body["average_risk_score"] <= 100

    def test_the_summary_counts_unique_domains(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": OTHER_SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/reports/summary").json()
        assert body["total_scans"] == 3
        assert body["unique_domains"] == 3


class TestCsvExport:
    def test_the_export_returns_a_csv_document(self, client: TestClient) -> None:
        response = client.get("/api/v1/reports/export.csv")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert "phishguard-scans.csv" in response.headers["content-disposition"]

    def test_the_export_contains_the_header_row(self, client: TestClient) -> None:
        response = client.get("/api/v1/reports/export.csv")
        rows = list(csv.reader(io.StringIO(response.text)))
        assert rows[0] == [
            "scan_id",
            "created_at",
            "submitted_url",
            "normalized_url",
            "hostname",
            "registrable_domain",
            "status",
            "classification",
            "phishing_probability",
            "risk_score",
            "model_version",
            "duration_ms",
        ]

    def test_the_export_has_one_row_per_scan(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        response = client.get("/api/v1/reports/export.csv")
        rows = list(csv.reader(io.StringIO(response.text)))
        assert len(rows) == 3  # header + two scans

    def test_the_export_contains_the_submitted_urls(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        response = client.get("/api/v1/reports/export.csv")
        rows = list(csv.reader(io.StringIO(response.text)))
        assert rows[1][2] == SAFE_URL

    def test_the_export_never_contains_credentials(self, client: TestClient) -> None:
        client.post(
            "/api/v1/scan",
            json={"url": "https://user:secretpassword@example.com/login"},
        )
        response = client.get("/api/v1/reports/export.csv")
        body = response.text
        # The submitted_url is redacted before persistence, so credentials
        # should never appear in the CSV export.
        assert "secretpassword" not in body
        # But the redaction should not remove the host entirely
        assert "example.com" in body

    def test_the_export_respects_the_limit(self, client: TestClient) -> None:
        for index in range(3):
            client.post(
                "/api/v1/scan", json={"url": f"https://example{index}.com/page"}
            )
        response = client.get("/api/v1/reports/export.csv", params={"limit": 2})
        rows = list(csv.reader(io.StringIO(response.text)))
        assert len(rows) == 3  # header + two exported rows

    def test_an_invalid_limit_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/v1/reports/export.csv", params={"limit": 0})
        assert response.status_code == 422
