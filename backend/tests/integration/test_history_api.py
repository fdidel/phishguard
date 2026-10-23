"""Integration tests for the scan history endpoints.

Covers ``GET /api/v1/scans`` (list + filters + pagination) and
``GET /api/v1/scans/{scan_id}`` (detail).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

SAFE_URL = "https://www.google.com/search?q=test"
DANGEROUS_URL = "http://paypa1-secure-login-verify.example/account/update?id=3"
OTHER_SAFE_URL = "https://en.wikipedia.org/wiki/Phishing"


class TestScanHistoryList:
    def test_an_empty_history_returns_an_empty_page(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["page"] == 1
        assert body["page_size"] == 20
        assert body["pages"] == 0

    def test_submitted_scans_appear_in_the_history(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/scans").json()
        assert body["total"] == 2
        assert len(body["items"]) == 2
        urls = {item["submitted_url"] for item in body["items"]}
        assert urls == {SAFE_URL, DANGEROUS_URL}

    def test_the_history_is_sorted_newest_first(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        items = client.get("/api/v1/scans").json()["items"]
        assert items[0]["submitted_url"] == DANGEROUS_URL

    def test_the_history_can_be_filtered_by_classification(
        self, client: TestClient
    ) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/scans", params={"classification": "dangerous"}).json()
        assert body["total"] == 1
        assert body["items"][0]["classification"] == "dangerous"

    def test_the_history_can_be_filtered_by_status(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": "ftp://example.com/file"})
        body = client.get("/api/v1/scans", params={"status": "failed"}).json()
        assert body["total"] == 1
        assert body["items"][0]["status"] == "failed"

    def test_the_history_can_be_filtered_by_domain(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": DANGEROUS_URL})
        body = client.get("/api/v1/scans", params={"domain": "paypa1-secure-login-verify.example"}).json()
        assert body["total"] == 1
        assert body["items"][0]["hostname"].endswith("example")

    def test_the_history_can_be_searched_by_url(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        client.post("/api/v1/scan", json={"url": OTHER_SAFE_URL})
        body = client.get("/api/v1/scans", params={"search": "wikipedia"}).json()
        assert body["total"] == 1
        assert body["items"][0]["submitted_url"] == OTHER_SAFE_URL

    def test_a_search_without_matches_returns_nothing(
        self, client: TestClient
    ) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        body = client.get("/api/v1/scans", params={"search": "no-such-host"}).json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_the_history_is_paginated(self, client: TestClient) -> None:
        for index in range(5):
            client.post(
                "/api/v1/scan", json={"url": f"https://example{index}.com/page"}
            )
        body = client.get("/api/v1/scans", params={"page": 1, "page_size": 2}).json()
        assert body["total"] == 5
        assert len(body["items"]) == 2
        assert body["page"] == 1
        assert body["page_size"] == 2
        assert body["pages"] == 3

        second = client.get("/api/v1/scans", params={"page": 3, "page_size": 2}).json()
        assert len(second["items"]) == 1

    def test_a_page_beyond_the_end_is_empty(self, client: TestClient) -> None:
        client.post("/api/v1/scan", json={"url": SAFE_URL})
        body = client.get("/api/v1/scans", params={"page": 9, "page_size": 10}).json()
        assert body["total"] == 1
        assert body["items"] == []

    def test_an_unknown_status_filter_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans", params={"status": "not-a-status"})
        assert response.status_code == 422

    def test_an_unknown_classification_filter_is_rejected(
        self, client: TestClient
    ) -> None:
        response = client.get(
            "/api/v1/scans", params={"classification": "not-a-classification"}
        )
        assert response.status_code == 422

    def test_an_invalid_page_number_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans", params={"page": 0})
        assert response.status_code == 422

    def test_an_oversized_page_size_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans", params={"page_size": 5000})
        assert response.status_code == 422


class TestScanHistoryDetail:
    def test_the_detail_of_a_scan_is_returned(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        response = client.get(f"/api/v1/scans/{submitted['scan_id']}")
        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"] == submitted["scan_id"]
        assert body["submitted_url"] == SAFE_URL
        assert body["status"] == "completed"
        assert body["classification"] == "safe"

    def test_the_detail_keeps_the_extracted_features(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": SAFE_URL}).json()
        body = client.get(f"/api/v1/scans/{submitted['scan_id']}").json()
        assert body["features"] is not None
        assert len(body["features"]) == 35

    def test_the_detail_keeps_the_evidence(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": DANGEROUS_URL}).json()
        body = client.get(f"/api/v1/scans/{submitted['scan_id']}").json()
        assert len(body["indicators"]) > 0
        for indicator in body["indicators"]:
            assert indicator["category"]
            assert indicator["description"]

    def test_the_detail_keeps_the_guidance(self, client: TestClient) -> None:
        submitted = client.post("/api/v1/scan", json={"url": DANGEROUS_URL}).json()
        body = client.get(f"/api/v1/scans/{submitted['scan_id']}").json()
        assert body["guidance"]
        assert "credential" in body["guidance"].lower()

    def test_the_detail_of_a_failed_scan_keeps_the_error_code(
        self, client: TestClient
    ) -> None:
        submitted = client.post(
            "/api/v1/scan", json={"url": "ftp://example.com/file"}
        ).json()
        body = client.get(f"/api/v1/scans/{submitted['scan_id']}").json()
        assert body["status"] == "failed"
        assert body["classification"] == "unknown"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"
        assert body["risk_score"] is None

    def test_an_unknown_scan_id_returns_404(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        body = response.json()
        assert "error" in body
        assert "message" in body

    def test_a_malformed_scan_id_returns_404(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans/not-a-uuid")
        assert response.status_code == 404
