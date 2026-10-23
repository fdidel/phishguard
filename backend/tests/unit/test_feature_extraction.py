"""Unit tests for the shared feature extractor.

The extractor is the single source of truth for the model's inputs: the same
function is used by the training pipeline and by the live API.  These tests
therefore assert on the *contract* (all features present, finite numbers,
stable ordering) rather than on individual feature values.
"""

from __future__ import annotations

import math

import pytest

from phishguard.feature_extraction import (
    extract_features,
    extract_features_batch,
    extract_features_from_url,
    feature_vector,
    feature_vector_from_url,
    get_feature,
    shannon_entropy,
)
from phishguard.feature_schema import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    NUM_FEATURES,
    assert_feature_order,
    feature_specs_as_dict,
)
from phishguard.url_validation import validate_url

SAMPLE_URLS = [
    "https://www.google.com/search?q=test",
    "http://paypa1-secure-login-verify.example/account/update?id=3",
    "https://github.com/anthropics/claude",
    "https://bit.ly/3xYzAbC",
    "https://sub.domain.example.co.uk/a/b/c?x=1&y=2#frag",
    "http://192.168.0.1/admin",
]


class TestFeatureSchema:
    def test_schema_version_is_declared(self) -> None:
        assert FEATURE_SCHEMA_VERSION
        assert FEATURE_SCHEMA_VERSION.count(".") == 2

    def test_feature_names_are_unique(self) -> None:
        assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)

    def test_num_features_matches_the_name_list(self) -> None:
        assert NUM_FEATURES == len(FEATURE_NAMES)
        assert NUM_FEATURES == 35

    def test_assert_feature_order_accepts_the_canonical_order(self) -> None:
        assert_feature_order(FEATURE_NAMES)

    def test_assert_feature_order_rejects_a_reordering(self) -> None:
        reordered = (FEATURE_NAMES[1], FEATURE_NAMES[0]) + FEATURE_NAMES[2:]
        with pytest.raises(ValueError):
            assert_feature_order(reordered)

    def test_every_feature_has_a_documented_specification(self) -> None:
        specs = feature_specs_as_dict()
        assert set(specs) == set(FEATURE_NAMES)
        for name, spec in specs.items():
            assert spec.get("meaning"), f"{name} has no meaning"
            assert spec.get("dtype"), f"{name} has no dtype"
            assert spec.get("extraction"), f"{name} has no extraction rule"
            assert spec.get("missing_value_policy"), f"{name} has no missing-value policy"
            assert spec.get("source"), f"{name} has no source"


class TestExtraction:
    @pytest.mark.parametrize("url", SAMPLE_URLS)
    def test_extraction_returns_every_feature(self, url: str) -> None:
        features = extract_features_from_url(url)
        assert set(features) == set(FEATURE_NAMES)
        assert len(features) == NUM_FEATURES

    @pytest.mark.parametrize("url", SAMPLE_URLS)
    def test_all_feature_values_are_finite_numbers(self, url: str) -> None:
        for name, value in extract_features_from_url(url).items():
            assert isinstance(value, (int, float)), name
            assert math.isfinite(value), name

    @pytest.mark.parametrize("url", SAMPLE_URLS)
    def test_extraction_is_deterministic(self, url: str) -> None:
        assert extract_features_from_url(url) == extract_features_from_url(url)

    def test_extraction_accepts_a_validated_url(self) -> None:
        validated = validate_url("https://example.com/login")
        assert extract_features(validated) == extract_features_from_url(
            "https://example.com/login"
        )

    def test_feature_vector_matches_the_declared_order(self) -> None:
        values = extract_features_from_url("https://example.com/login")
        vector = feature_vector_from_url("https://example.com/login")
        assert len(vector) == NUM_FEATURES
        assert vector == [values[name] for name in FEATURE_NAMES]

    def test_feature_vector_from_validated_url_matches(self) -> None:
        validated = validate_url("https://example.com/login")
        assert feature_vector(validated) == feature_vector_from_url(
            "https://example.com/login"
        )

    def test_batch_extraction_keeps_the_input_order(self) -> None:
        vectors, errors = extract_features_batch(SAMPLE_URLS)
        assert errors == []
        assert len(vectors) == len(SAMPLE_URLS)
        assert vectors[0] == feature_vector_from_url(SAMPLE_URLS[0])
        assert vectors[-1] == feature_vector_from_url(SAMPLE_URLS[-1])

    def test_batch_extraction_reports_the_failing_rows(self) -> None:
        vectors, errors = extract_features_batch(["https://example.com", "javascript:alert(1)"])
        assert len(vectors) == 1
        assert len(errors) == 1

    def test_get_feature_returns_none_for_an_unknown_feature(self) -> None:
        values = extract_features_from_url("https://example.com")
        assert get_feature("this_feature_does_not_exist", values) is None

    def test_get_feature_returns_the_value_for_a_known_feature(self) -> None:
        values = extract_features_from_url("https://example.com")
        name = FEATURE_NAMES[0]
        assert get_feature(name, values) == values[name]


class TestDiscriminatingFeatures:
    """A few features must actually react to the URL, otherwise the model
    could not possibly work."""

    def test_url_length_feature_tracks_the_length(self) -> None:
        short = extract_features_from_url("https://example.com/a")
        long = extract_features_from_url("https://example.com/" + "a" * 300)
        length_feature = next(
            name for name in FEATURE_NAMES if "length" in name and "url" in name
        )
        assert long[length_feature] > short[length_feature]

    def test_keyword_feature_reacts_to_phishing_keywords(self) -> None:
        clean = extract_features_from_url("https://example.com/articles")
        keyworded = extract_features_from_url(
            "https://example.com/login/verify/secure/update-password"
        )
        keyword_feature = next(
            name for name in FEATURE_NAMES if "keyword" in name
        )
        assert keyworded[keyword_feature] > clean[keyword_feature]

    def test_entropy_feature_reacts_to_random_subdomains(self) -> None:
        plain = extract_features_from_url("https://example.com/a")
        randomish = extract_features_from_url(
            "https://a8f3k2mz9q7b4x6c1.example.com/a"
        )
        entropy_feature = next(
            name for name in FEATURE_NAMES if "entropy" in name
        )
        assert randomish[entropy_feature] > plain[entropy_feature]

    def test_ip_host_feature_reacts_to_ip_literals(self) -> None:
        domain = extract_features_from_url("https://example.com/a")
        ip_literal = extract_features_from_url("http://203.0.113.10/a")
        ip_feature = next(name for name in FEATURE_NAMES if "ip" in name)
        assert ip_literal[ip_feature] != domain[ip_feature]


class TestEntropy:
    def test_entropy_of_a_uniform_string_is_zero(self) -> None:
        assert shannon_entropy("aaaa") == pytest.approx(0.0)

    def test_entropy_of_two_equally_likely_symbols_is_one_bit(self) -> None:
        assert shannon_entropy("abab") == pytest.approx(1.0)

    def test_entropy_of_an_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == pytest.approx(0.0)

    def test_entropy_grows_with_the_alphabet_size(self) -> None:
        assert shannon_entropy("abcd") > shannon_entropy("ab")
