"""
Canonical URL feature extraction.

This module is the *only* implementation of feature extraction in the project.
Both the offline training pipeline (``ml/src``) and the online API
(``backend/app``) import it, which guarantees feature parity between training
and inference.

Every function here is pure and deterministic: the same URL always yields the
same feature vector, on any machine, in any process.
"""

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Sequence, Tuple

from phishguard.feature_schema import (
    BRAND_OFFICIAL_DOMAINS,
    FEATURE_NAMES,
    RISKY_TLDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
)
from phishguard.url_validation import ValidatedUrl, validate_url

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Punctuation that is considered "normal" inside a URL and therefore is not
#: counted towards the special-character feature.
_ALLOWED_PUNCTUATION = set(".-_~:/?#[]@!$&'()*+,;=%")

#: Percent-escape sequence, e.g. %20, %2F.
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

#: Anything that is not an alphanumeric character is a token separator.
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

#: Risk suffixes are compared without the leading dot.
_RISKY_TLD_SET = frozenset(RISKY_TLDS)
_SHORTENER_SET = frozenset(SHORTENER_DOMAINS)

#: Lower-cased URL body used for keyword/brand matching.
_BRAND_TOKEN_RE = re.compile(r"[a-z0-9]+")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits of the character distribution of ``text``.

    Returns ``0.0`` for an empty string.
    """
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _tokens(text: str) -> List[str]:
    """Split ``text`` into lower-cased alphanumeric tokens."""
    return [tok for tok in _TOKEN_SPLIT_RE.split(text.lower()) if tok]


def _count_brand_mismatches(url_lower: str, registrable_domain: str) -> int:
    """Count brand tokens in ``url_lower`` that do not belong to this domain.

    ``https://paypal.secure-login.example/verify`` contains the brand token
    ``paypal`` although the registrable domain is ``example`` -> 1 mismatch.
    """
    if not url_lower:
        return 0
    url_tokens = set(_BRAND_TOKEN_RE.findall(url_lower))
    if not url_tokens:
        return 0

    domain_tokens = set(_BRAND_TOKEN_RE.findall(registrable_domain.lower()))
    domain_suffixes = {
        dom.lower() for doms in BRAND_OFFICIAL_DOMAINS.values() for dom in doms
    }

    mismatches = 0
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand not in url_tokens:
            continue
        if brand in domain_tokens:
            # The brand appears inside the registrable domain itself.
            # Only count it as a mismatch when this domain is not an
            # official domain of the brand (e.g. "paypal-secure.com").
            if registrable_domain.lower() in official_domains:
                continue
            if registrable_domain.lower() in domain_suffixes:
                continue
            mismatches += 1
            continue
        mismatches += 1
    return mismatches


def _count_suspicious_keywords(url_lower: str) -> int:
    """Count distinct phishing-intent keywords present in the lower-cased URL."""
    if not url_lower:
        return 0
    hits = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            hits += 1
    return hits


def _public_suffix(hostname: str) -> str:
    """Best-effort public suffix extraction (without a second tldextract call)."""
    # The registrable domain is "<name>.<suffix>"; for multi-part suffixes
    # ("co.uk") we still get a reasonable answer for the risky-TLD check.
    parts = hostname.split(".")
    if len(parts) >= 2:
        return parts[-1]
    return ""


# --------------------------------------------------------------------------
# Core extraction
# --------------------------------------------------------------------------


def extract_features(validated: ValidatedUrl) -> Dict[str, float]:
    """Extract the canonical feature vector from a validated URL.

    Parameters
    ----------
    validated:
        A :class:`~phishguard.url_validation.ValidatedUrl` produced by
        :func:`~phishguard.url_validation.validate_url`.

    Returns
    -------
    dict
        Mapping of feature name -> float value.  Keys are exactly
        ``phishguard.feature_schema.FEATURE_NAMES``.
    """
    url = validated.normalized_url
    url_lower = url.lower()
    hostname = validated.hostname.lower()
    hostname_lower = hostname

    url_length = len(url)
    path = validated.path or ""
    query = validated.query or ""

    path_length = len(path)
    query_length = len(query)

    num_dots_total = url.count(".")
    num_digits_total = sum(1 for ch in url if ch.isdigit())
    digit_ratio_total = num_digits_total / url_length if url_length else 0.0

    num_special_chars_total = sum(
        1 for ch in url if not ch.isalnum() and ch not in _ALLOWED_PUNCTUATION
    )
    special_char_ratio_total = (
        num_special_chars_total / url_length if url_length else 0.0
    )

    host_labels = validated.host_labels or tuple(
        label for label in hostname.split(".") if label
    )
    num_subdomains = max(0, len(host_labels) - 2) if len(host_labels) > 2 else 0

    has_ip_address = 1 if (validated.is_ip_host and not validated.is_ipv6) else 0
    has_ipv6_address = 1 if validated.is_ipv6 else 0

    has_at_symbol = 1 if (validated.has_userinfo or "@" in path or "@" in query) else 0

    uses_https = 1 if validated.scheme == "https" else 0
    scheme_inferred = 1 if validated.scheme_inferred else 0

    path_segments = [segment for segment in path.split("/") if segment]
    path_depth = len(path_segments)
    num_query_params = len([param for param in query.split("&") if param])

    url_entropy = shannon_entropy(url)
    hostname_entropy = shannon_entropy(hostname)

    has_double_slash_in_path = 1 if "//" in path else 0
    has_port = 1 if validated.port is not None else 0

    registrable = validated.registrable_domain.lower()
    known_shortener = 1 if registrable in _SHORTENER_SET else 0

    suspicious_keyword_count = _count_suspicious_keywords(url_lower)
    risky_tld = 1 if _public_suffix(hostname_lower) in _RISKY_TLD_SET else 0
    punycode_hostname = 1 if "xn--" in hostname_lower else 0
    has_percent_encoding = 1 if _PERCENT_ESCAPE_RE.search(url) else 0

    host_tokens = _tokens(hostname)
    hostname_token_count = len(host_tokens)
    avg_hostname_token_length = (
        sum(len(token) for token in host_tokens) / hostname_token_count
        if hostname_token_count
        else 0.0
    )

    all_tokens = _tokens(url)
    max_token_length = max((len(token) for token in all_tokens), default=0)

    brand_mismatch_count = _count_brand_mismatches(url_lower, registrable)

    num_underscores_total = url.count("_")
    num_tilde_total = url.count("~")
    path_depth_ratio = path_depth / url_length if url_length else 0.0

    values: Dict[str, float] = {
        "url_length": float(url_length),
        "hostname_length": float(len(hostname)),
        "path_length": float(path_length),
        "query_length": float(query_length),
        "num_dots_total": float(num_dots_total),
        "num_subdomains": float(num_subdomains),
        "num_digits_total": float(num_digits_total),
        "digit_ratio_total": float(digit_ratio_total),
        "num_special_chars_total": float(num_special_chars_total),
        "special_char_ratio_total": float(special_char_ratio_total),
        "num_hyphens_hostname": float(hostname.count("-")),
        "hostname_digit_count": float(sum(1 for ch in hostname if ch.isdigit())),
        "has_ip_address": float(has_ip_address),
        "has_ipv6_address": float(has_ipv6_address),
        "has_at_symbol": float(has_at_symbol),
        "uses_https": float(uses_https),
        "scheme_inferred": float(scheme_inferred),
        "path_depth": float(path_depth),
        "num_query_params": float(num_query_params),
        "url_entropy": float(url_entropy),
        "hostname_entropy": float(hostname_entropy),
        "has_double_slash_in_path": float(has_double_slash_in_path),
        "has_port": float(has_port),
        "known_shortener": float(known_shortener),
        "suspicious_keyword_count": float(suspicious_keyword_count),
        "risky_tld": float(risky_tld),
        "punycode_hostname": float(punycode_hostname),
        "has_percent_encoding": float(has_percent_encoding),
        "hostname_token_count": float(hostname_token_count),
        "avg_hostname_token_length": float(avg_hostname_token_length),
        "max_token_length": float(max_token_length),
        "brand_mismatch_count": float(brand_mismatch_count),
        "num_underscores_total": float(num_underscores_total),
        "num_tilde_total": float(num_tilde_total),
        "path_depth_ratio": float(path_depth_ratio),
    }

    # Hard guarantee: the produced vector matches the canonical schema exactly.
    if set(values) != set(FEATURE_NAMES):
        missing = set(FEATURE_NAMES) - set(values)
        extra = set(values) - set(FEATURE_NAMES)
        raise RuntimeError(
            f"Feature schema mismatch (missing={sorted(missing)}, extra={sorted(extra)})"
        )
    return values


def extract_features_from_url(raw_url: str) -> Dict[str, float]:
    """Validate ``raw_url`` and extract its feature vector.

    Raises
    ------
    UrlValidationError
        If the URL cannot be validated.
    """
    return extract_features(validate_url(raw_url))


def feature_vector(validated: ValidatedUrl) -> List[float]:
    """Return the feature vector as an ordered list matching ``FEATURE_NAMES``."""
    values = extract_features(validated)
    return [float(values[name]) for name in FEATURE_NAMES]


def feature_vector_from_url(raw_url: str) -> List[float]:
    """Validate ``raw_url`` and return the ordered feature vector."""
    return feature_vector(validate_url(raw_url))


def extract_features_batch(urls: Sequence[str]) -> Tuple[List[List[float]], List[str]]:
    """Extract feature vectors for a sequence of URLs.

    URLs that fail validation are skipped and reported through the second
    return value (the list of failure messages).  This keeps the training
    pipeline able to drop unusable rows while still accounting for them.

    Returns
    -------
    (vectors, errors)
        ``vectors`` is a list of ordered feature lists; ``errors`` is a list of
        human-readable messages, one per rejected URL.
    """
    vectors: List[List[float]] = []
    errors: List[str] = []
    for raw in urls:
        try:
            vectors.append(feature_vector_from_url(raw))
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            errors.append(f"{raw!r}: {exc}")
    return vectors, errors


def describe_feature_values(values: Dict[str, float]) -> Dict[str, float]:
    """Return the feature values as plain floats (JSON friendly)."""
    return {name: float(values[name]) for name in FEATURE_NAMES}


def numeric_feature_names() -> Tuple[str, ...]:
    """Names of the features that are numeric (all of them, by construction)."""
    return FEATURE_NAMES


def optional_feature_names() -> Tuple[str, ...]:
    """Features that may legitimately be unavailable (none in the URL model)."""
    return ()


def get_feature(name: str, values: Dict[str, float]) -> Optional[float]:
    """Safely read a feature value, returning ``None`` when unavailable."""
    return values.get(name)
