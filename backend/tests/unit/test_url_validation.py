"""Unit tests for URL validation and normalisation.

These tests cover the rules that keep the feature extractor and the SSRF guard
working on a well-defined input: only HTTP(S) is accepted, the hostname has to
be a valid DNS name, the registrable domain is extracted, and the result is
normalised deterministically.
"""

from __future__ import annotations

import pytest

from phishguard.url_validation import (
    MAX_URL_LENGTH,
    UrlValidationError,
    is_valid_url,
    normalize_url,
    split_registrable_domain,
    validate_url,
)


class TestValidUrls:
    def test_accepts_a_plain_https_url(self) -> None:
        validated = validate_url("https://example.com/login")
        assert validated.scheme == "https"
        assert validated.hostname == "example.com"
        assert validated.registrable_domain == "example.com"
        assert validated.subdomain == ""
        assert validated.path == "/login"

    def test_accepts_http(self) -> None:
        assert validate_url("http://example.com").scheme == "http"

    def test_assumes_https_when_the_scheme_is_missing(self) -> None:
        validated = validate_url("example.com/login")
        assert validated.scheme == "https"
        assert validated.scheme_inferred is True
        assert validated.hostname == "example.com"

    def test_keeps_an_explicit_scheme_flagged_as_not_inferred(self) -> None:
        assert validate_url("https://example.com").scheme_inferred is False

    def test_lowercases_the_hostname(self) -> None:
        assert validate_url("https://EXAMPLE.COM/Path").hostname == "example.com"

    def test_keeps_the_path_case(self) -> None:
        assert validate_url("https://example.com/Some/Path").path == "/Some/Path"

    def test_strips_leading_and_trailing_whitespace(self) -> None:
        validated = validate_url("  https://example.com/login  ")
        assert validated.original_input == "  https://example.com/login  "
        assert validated.hostname == "example.com"

    def test_extracts_the_registrable_domain(self) -> None:
        validated = validate_url("https://login.secure.example.co.uk/x")
        assert validated.hostname == "login.secure.example.co.uk"
        assert validated.registrable_domain == "example.co.uk"
        assert validated.subdomain == "login.secure"

    def test_records_an_explicit_port(self) -> None:
        assert validate_url("https://example.com:8443/x").port == 8443

    def test_records_the_query_string_and_fragment(self) -> None:
        validated = validate_url("https://example.com/p?a=1&b=2#frag")
        assert validated.query == "a=1&b=2"
        assert validated.fragment == "frag"

    def test_detects_userinfo(self) -> None:
        assert validate_url("https://user:pass@example.com/x").has_userinfo is True

    def test_detects_ip_literal_hosts(self) -> None:
        validated = validate_url("http://192.168.0.1/admin")
        assert validated.is_ip_host is True
        assert validated.hostname == "192.168.0.1"

    def test_detects_ipv6_literal_hosts(self) -> None:
        validated = validate_url("http://[::1]/admin")
        assert validated.is_ipv6 is True
        assert validated.host_for_display == "[::1]"

    def test_idna_encodes_a_unicode_hostname(self) -> None:
        validated = validate_url("https://exämple.com/x")
        # Punycode of the label "exämple" is "xn--exmple-cua".
        assert validated.hostname == "xn--exmple-cua.com"
        assert validated.host_labels[0].startswith("xn--")
        assert validated.normalized_url.startswith("https://xn--")


class TestInvalidUrls:
    def test_rejects_an_empty_string(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("")

    def test_rejects_whitespace_only(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("   ")

    def test_rejects_an_oversized_url(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("https://example.com/" + "a" * MAX_URL_LENGTH)

    def test_rejects_a_non_http_scheme(self) -> None:
        for url in (
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "mailto:someone@example.com",
        ):
            with pytest.raises(UrlValidationError):
                validate_url(url)

    def test_rejects_a_hostname_with_spaces(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("https://exa mple.com")

    def test_rejects_a_missing_hostname(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("https:///path")

    def test_rejects_control_characters(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("https://example.com/\x00path")

    def test_rejects_an_overlong_hostname(self) -> None:
        long_host = ".".join(["a" * 60] * 5)
        with pytest.raises(UrlValidationError):
            validate_url(f"https://{long_host}/")

    def test_rejects_an_overlong_label(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url(f"https://{'a' * 64}.example.com/")

    def test_rejects_a_hostname_starting_with_a_hyphen(self) -> None:
        with pytest.raises(UrlValidationError):
            validate_url("https://-bad.example.com/")

    def test_error_carries_a_code_and_a_message(self) -> None:
        with pytest.raises(UrlValidationError) as excinfo:
            validate_url("javascript:alert(1)")
        assert excinfo.value.code
        assert excinfo.value.message

    def test_is_valid_url_matches_validate_url(self) -> None:
        assert is_valid_url("https://example.com") is True
        assert is_valid_url("javascript:alert(1)") is False
        assert is_valid_url("") is False


class TestNormalisation:
    def test_normalisation_is_deterministic(self) -> None:
        first = normalize_url("https://example.com/a")
        second = normalize_url("https://example.com/a")
        assert first == second

    def test_normalisation_keeps_the_scheme_and_host(self) -> None:
        assert normalize_url("https://example.com/login").startswith("https://example.com")

    def test_normalisation_of_an_invalid_url_raises(self) -> None:
        with pytest.raises(UrlValidationError):
            normalize_url("javascript:alert(1)")


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        "hostname,expected",
        [
            ("example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("a.b.c.example.com", "example.com"),
            ("example.co.uk", "example.co.uk"),
            ("login.example.com.ng", "example.com.ng"),
        ],
    )
    def test_split_registrable_domain(self, hostname: str, expected: str) -> None:
        registrable, _ = split_registrable_domain(hostname)
        assert registrable == expected
