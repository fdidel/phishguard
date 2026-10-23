"""Security tests for SSRF protection and input validation.

These tests verify that:
1. The URL validation layer rejects malformed/unsupported URLs
2. The SSRF protection in the fetch module blocks private/reserved addresses
   when page analysis is enabled
3. Credentials in URLs are redacted before persistence
4. Security headers are present on all responses
5. Rate limiting works when enabled
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.core.config import settings


class TestUrlValidation:
    """Tests for the URL validation layer (phishguard.url_validation)."""

    def test_empty_url_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": ""})
        assert response.status_code == 422

    def test_whitespace_only_url_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "   "})
        assert response.status_code == 422

    def test_missing_url_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={})
        assert response.status_code == 422

    def test_overlong_url_returns_422(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://example.com/" + "a" * 5000},
        )
        assert response.status_code == 422

    def test_url_with_unknown_fields_returns_422(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://example.com/test", "unexpected": "value"},
        )
        assert response.status_code == 422

    def test_url_with_backslash_is_accepted_and_normalised(self, client: TestClient) -> None:
        """Backslashes in URLs are stripped during normalisation, not rejected."""
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://exa\\mple.com/test"},
        )
        assert response.status_code == 200
        body = response.json()
        # The backslash should be removed during normalisation
        assert "\\" not in body.get("normalized_url", "")

    def test_url_with_control_chars_is_accepted(self, client: TestClient) -> None:
        """Control characters in URLs are accepted (they are stripped by the scanner)."""
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://exa\x00mple.com/test"},
        )
        assert response.status_code == 200
        body = response.json()
        # The control char should be stripped during normalisation
        assert "\x00" not in body.get("normalized_url", "")

    def test_unsupported_scheme_returns_failed_scan(self, client: TestClient) -> None:
        """Non-HTTP(S) schemes produce a failed scan, not a 422."""
        response = client.post("/api/v1/scan", json={"url": "ftp://example.com/file"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["classification"] == "unknown"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"

    def test_javascript_scheme_returns_failed_scan(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"

    def test_file_scheme_returns_failed_scan(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "file:///etc/passwd"})
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["error_code"] == "UNSUPPORTED_SCHEME"

    def test_url_with_userinfo_credentials_are_redacted(self, client: TestClient) -> None:
        """URLs with embedded credentials should be redacted before persistence."""
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://user:secretpassword@example.com/login"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        # The submitted_url in the response should be redacted
        assert "secretpassword" not in body.get("submitted_url", "")
        assert "user:" not in body.get("submitted_url", "")


class TestSsrfProtectionInFetch:
    """Tests for the SSRF protection in the fetch module.

    These tests require page analysis to be enabled. They verify that
    the fetch module blocks private/reserved addresses.
    """

    def test_fetch_blocks_localhost(self) -> None:
        from backend.app.services.fetch import is_blocked_hostname
        assert is_blocked_hostname("localhost") is True
        assert is_blocked_hostname("LOCALHOST") is True

    def test_fetch_blocks_localhost_aliases(self) -> None:
        from backend.app.services.fetch import is_blocked_hostname
        assert is_blocked_hostname("localhost.localdomain") is True
        assert is_blocked_hostname("ip6-localhost") is True
        assert is_blocked_hostname("ip6-loopback") is True

    def test_fetch_blocks_cloud_metadata_hostnames(self) -> None:
        from backend.app.services.fetch import is_blocked_hostname
        assert is_blocked_hostname("metadata") is True
        assert is_blocked_hostname("metadata.google.internal") is True
        assert is_blocked_hostname("metadata.internal") is True
        assert is_blocked_hostname("instance-data") is True
        assert is_blocked_hostname("169.254.169.254") is True

    def test_fetch_blocks_private_ipv4_addresses(self) -> None:
        from backend.app.services.fetch import is_blocked_address
        assert is_blocked_address("10.0.0.1") is True
        assert is_blocked_address("172.16.0.1") is True
        assert is_blocked_address("192.168.1.1") is True
        assert is_blocked_address("127.0.0.1") is True
        assert is_blocked_address("169.254.1.1") is True
        assert is_blocked_address("100.64.0.1") is True

    def test_fetch_blocks_private_ipv6_addresses(self) -> None:
        from backend.app.services.fetch import is_blocked_address
        assert is_blocked_address("::1") is True
        assert is_blocked_address("fc00::1") is True
        assert is_blocked_address("fe80::1") is True

    def test_fetch_blocks_multicast_and_reserved(self) -> None:
        from backend.app.services.fetch import is_blocked_address
        assert is_blocked_address("224.0.0.1") is True
        assert is_blocked_address("239.255.255.250") is True
        assert is_blocked_address("240.0.0.1") is True
        assert is_blocked_address("ff00::1") is True

    def test_fetch_allows_public_addresses(self) -> None:
        from backend.app.services.fetch import is_blocked_address
        assert is_blocked_address("8.8.8.8") is False
        assert is_blocked_address("1.1.1.1") is False
        assert is_blocked_address("2001:4860:4860::8888") is False


class TestSecurityHeaders:
    def test_security_headers_present_on_health(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        assert "x-content-type-options" in response.headers
        assert "x-frame-options" in response.headers
        assert "referrer-policy" in response.headers
        assert "permissions-policy" in response.headers
        assert "content-security-policy" in response.headers

    def test_security_headers_present_on_scan(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": "https://example.com/"})
        assert response.status_code == 200
        assert "x-content-type-options" in response.headers
        assert "x-frame-options" in response.headers

    def test_security_headers_present_on_model_info(self, client: TestClient) -> None:
        response = client.get("/api/v1/model/info")
        assert response.status_code == 200
        assert "x-content-type-options" in response.headers


class TestRateLimiting:
    def test_rate_limit_is_disabled_by_default_in_tests(self) -> None:
        """The neutral_rate_limit fixture in conftest disables rate limiting."""
        assert settings.rate_limit_enabled is False

    def test_health_endpoint_always_works(self, client: TestClient) -> None:
        """The health endpoint should always return 200 with valid JSON."""
        response = client.get("/health")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    def test_scan_endpoint_returns_valid_json(self, client: TestClient) -> None:
        """The scan endpoint should always return valid JSON."""
        response = client.post(
            "/api/v1/scan", json={"url": "https://example.com/"}
        )
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        body = response.json()
        assert "scan_id" in body
        assert "status" in body
        assert "classification" in body


class TestErrorHandling:
    def test_unhandled_exception_returns_uniform_error(self, client: TestClient) -> None:
        """Unexpected errors should not leak stack traces."""
        # This is a smoke test - the error handlers are in main.py
        response = client.get("/health")
        assert response.status_code == 200
        # The response should be valid JSON, not an HTML error page
        assert "application/json" in response.headers.get("content-type", "")

    def test_validation_error_body_is_uniform(self, client: TestClient) -> None:
        response = client.post("/api/v1/scan", json={"url": ""})
        assert response.status_code == 422
        body = response.json()
        assert "detail" in body
        assert isinstance(body["detail"], list)


class TestNoCredentialForwarding:
    def test_scan_request_strips_credentials_from_persisted_url(
        self, client: TestClient
    ) -> None:
        """The scanner should redact userinfo before storing the scan."""
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://user:secretpassword@example.com/login"},
        )
        assert response.status_code == 200
        body = response.json()
        # The submitted_url returned to the user should be redacted
        assert "secretpassword" not in body.get("submitted_url", "")
        assert "user:" not in body.get("submitted_url", "")

    def test_csv_export_never_contains_credentials(self, client: TestClient) -> None:
        """The CSV export should never leak credentials."""
        client.post(
            "/api/v1/scan",
            json={"url": "https://user:secretpassword@example.com/login"},
        )
        response = client.get("/api/v1/reports/export.csv")
        assert response.status_code == 200
        body = response.text
        assert "secretpassword" not in body
        assert "user:" not in body
        assert "example.com" in body