"""
Canonical feature schema for the PhishGuard phishing detection model.

Every feature that the deployed model consumes is declared exactly once, here.
The schema is versioned; the version string is embedded into the saved model
artifact and is checked at load time by the backend.  A mismatch between the
artifact's schema version and the running code causes a loud, explicit failure
rather than a silently mis-prediction.

Design rules enforced by this module
------------------------------------
1. Every feature must be derivable from the URL string alone (plus the
   registrable-domain split).  Features that require fetching a page are
   deliberately excluded from the model and are handled separately as
   *supplementary evidence* (see ``phishguard.page_features``).
2. Every feature is numeric and finite.  There are no "unknown" placeholders:
   if a URL cannot be parsed at all the scan fails before feature extraction,
   so a missing feature never masquerades as evidence of safety.
3. Feature ORDER is part of the contract.  ``FEATURE_NAMES`` is the canonical
   ordering used to build the model input vector.

Missing-value policy
--------------------
All URL-lexical features are *always* available for a syntactically valid
URL.  The only exception is a URL whose host is malformed beyond repair, in
which case validation rejects the URL (HTTP 422) and no model input is built.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

# --------------------------------------------------------------------------
# Versioning
# --------------------------------------------------------------------------

#: Bump this whenever FEATURE_NAMES or the semantics of any feature change.
FEATURE_SCHEMA_VERSION = "1.0.0"

#: Name of the model trained against FEATURE_SCHEMA_VERSION.
DEFAULT_MODEL_VERSION = "phishguard-url-rf-1.0.0"


# --------------------------------------------------------------------------
# Reference vocabularies (documented in docs/dataset.md and docs/model_card.md)
# --------------------------------------------------------------------------

#: Generic intent words that are frequently used by credential-harvesting pages.
SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "account",
    "alert",
    "authenticate",
    "authorize",
    "banking",
    "billing",
    "bonus",
    "confirm",
    "confirmation",
    "credential",
    "expire",
    "gift",
    "invoice",
    "limited",
    "lottery",
    "login",
    "log-in",
    "otp",
    "password",
    "passwd",
    "payment",
    "prize",
    "recover",
    "refund",
    "secure",
    "security",
    "session",
    "signin",
    "sign-in",
    "suspended",
    "token",
    "unlock",
    "update",
    "urgent",
    "validate",
    "verification",
    "verify",
    "wallet",
    "winner",
)

#: Public-suffix values that are disproportionately used for bulk malicious
#: registrations (mostly free or newly-opened registries).
RISKY_TLDS: Tuple[str, ...] = (
    "buzz",
    "cam",
    "cf",
    "click",
    "country",
    "cyou",
    "fit",
    "ga",
    "gdn",
    "gq",
    "icu",
    "kim",
    "link",
    "loan",
    "lol",
    "men",
    "ml",
    "monster",
    "mov",
    "quest",
    "review",
    "rest",
    "sbs",
    "stream",
    "surf",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
)

#: Hostnames of well-known URL shortening services.
SHORTENER_DOMAINS: Tuple[str, ...] = (
    "1url.com",
    "adf.ly",
    "bit.do",
    "bit.ly",
    "buff.ly",
    "clck.ru",
    "cutt.ly",
    "db.tt",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "qr.ae",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
    "shorter.me",
    "tiny.cc",
    "tinyurl.com",
    "t.ly",
    "t.co",
    "u.to",
    "v.gd",
    "youtu.be",
)

#: Brand tokens mapped to the registrable domains that legitimately serve them.
#: Used to detect brand impersonation (e.g. ``paypal-secure.example``).
BRAND_OFFICIAL_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "aws.amazon.com"),
    "apple": ("apple.com", "icloud.com"),
    "barclays": ("barclays.co.uk", "barclays.com"),
    "binance": ("binance.com", "binance.us"),
    "chase": ("chase.com",),
    "coinbase": ("coinbase.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "discord": ("discord.com", "discord.gg"),
    "docusign": ("docusign.com",),
    "dropbox": ("dropbox.com",),
    "ebay": ("ebay.com",),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "fedex": ("fedex.com",),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com", "goo.gl"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "instagram": ("instagram.com",),
    "intesa": ("intesa.it"),
    "linkedin": ("linkedin.com",),
    "mail.ru": ("mail.ru",),
    "metamask": ("metamask.io",),
    "microsoft": (
        "microsoft.com",
        "live.com",
        "msn.com",
        "office.com",
        "office365.com",
        "sharepoint.com",
        "outlook.com",
        "hotmail.com",
    ),
    "netflix": ("netflix.com",),
    "outlook": ("outlook.com", "hotmail.com", "live.com", "microsoft.com"),
    "paypal": ("paypal.com",),
    "poste": ("poste.it", "poste.de"),
    "roblox": ("roblox.com",),
    "snapchat": ("snapchat.com",),
    "spotify": ("spotify.com",),
    "steam": ("steampowered.com", "steamcommunity.com", "valvesoftware.com"),
    "telegram": ("telegram.org", "t.me"),
    "tiktok": ("tiktok.com",),
    "twitter": ("twitter.com", "x.com"),
    "uber": ("uber.com",),
    "unicredit": ("unicredit.it",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "walmart": ("walmart.com",),
    "wellsfargo": ("wellsfargo.com",),
    "whatsapp": ("whatsapp.com",),
    "yahoo": ("yahoo.com", "ymail.com"),
    "zoom": ("zoom.us", "zoom.com"),
}


# --------------------------------------------------------------------------
# Feature specifications
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FeatureSpec:
    """Documentation of a single model input feature."""

    name: str
    dtype: str
    meaning: str
    extraction: str
    missing_value_policy: str
    source: str = "url"

    def as_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "dtype": self.dtype,
            "meaning": self.meaning,
            "extraction": self.extraction,
            "missing_value_policy": self.missing_value_policy,
            "source": self.source,
        }


_MISSING_POLICY = (
    "Always defined for a syntactically valid URL. A URL that cannot be parsed is "
    "rejected during validation, so this feature is never silently imputed."
)

FEATURE_SPECS: Tuple[FeatureSpec, ...] = (
    FeatureSpec("url_length", "int", "Total character length of the normalised URL.",
                 "len(normalized_url)", _MISSING_POLICY),
    FeatureSpec("hostname_length", "int", "Character length of the lower-cased hostname.",
                 "len(hostname)", _MISSING_POLICY),
    FeatureSpec("path_length", "int", "Character length of the URL path component.",
                 "len(urlsplit(path))", _MISSING_POLICY),
    FeatureSpec("query_length", "int", "Character length of the query string.",
                 "len(urlsplit(query))", _MISSING_POLICY),
    FeatureSpec("num_dots_total", "int", "Number of '.' characters in the whole URL.",
                 "normalized_url.count('.')", _MISSING_POLICY),
    FeatureSpec("num_subdomains", "int",
                 "Number of DNS labels preceding the registrable domain.",
                 "count(labels) - count(registrable_domain_labels)", _MISSING_POLICY),
    FeatureSpec("num_digits_total", "int", "Number of decimal digits in the whole URL.",
                 "sum(ch.isdigit())", _MISSING_POLICY),
    FeatureSpec("digit_ratio_total", "float", "Digits divided by total URL length.",
                 "num_digits_total / url_length", _MISSING_POLICY),
    FeatureSpec("num_special_chars_total", "int",
                 "Count of characters outside [A-Za-z0-9./-_~:/?#[]@!$&'()*+,;=%].",
                 "scan url characters against the allowed punctuation set", _MISSING_POLICY),
    FeatureSpec("special_char_ratio_total", "float",
                 "Special characters divided by total URL length.",
                 "num_special_chars_total / url_length", _MISSING_POLICY),
    FeatureSpec("num_hyphens_hostname", "int", "Number of '-' characters in the hostname.",
                 "hostname.count('-')", _MISSING_POLICY),
    FeatureSpec("hostname_digit_count", "int", "Number of digits in the hostname.",
                 "sum(ch.isdigit() for ch in hostname)", _MISSING_POLICY),
    FeatureSpec("has_ip_address", "int", "1 when the hostname is an IPv4 literal.",
                 "ipaddress.ip_address(hostname) is IPv4Address", _MISSING_POLICY),
    FeatureSpec("has_ipv6_address", "int", "1 when the hostname is an IPv6 literal.",
                 "ipaddress.ip_address(hostname) is IPv6Address", _MISSING_POLICY),
    FeatureSpec("has_at_symbol", "int",
                 "1 when the URL embeds userinfo ('user@host') or an '@' in path/query.",
                 "parsed.username is not None or '@' in path/query", _MISSING_POLICY),
    FeatureSpec("uses_https", "int", "1 when the scheme is https, else 0.",
                 "scheme == 'https'", _MISSING_POLICY),
    FeatureSpec("scheme_inferred", "int",
                 "1 when the scheme was added by the normaliser (user omitted it).",
                 "scheme_inferred flag from the validator", _MISSING_POLICY),
    FeatureSpec("path_depth", "int", "Number of non-empty path segments.",
                 "len([s for s in path.split('/') if s])", _MISSING_POLICY),
    FeatureSpec("num_query_params", "int", "Number of query-string parameters.",
                 "len([p for p in query.split('&') if p])", _MISSING_POLICY),
    FeatureSpec("url_entropy", "float",
                 "Shannon entropy (bits) of the character distribution of the URL.",
                 "-sum(p*log2(p)) over character frequencies", _MISSING_POLICY),
    FeatureSpec("hostname_entropy", "float",
                 "Shannon entropy (bits) of the character distribution of the hostname.",
                 "-sum(p*log2(p)) over character frequencies", _MISSING_POLICY),
    FeatureSpec("has_double_slash_in_path", "int",
                 "1 when the path contains '//' (a common redirect-style artefact).",
                 "'//' in path", _MISSING_POLICY),
    FeatureSpec("has_port", "int", "1 when an explicit TCP port is present.",
                 "urlsplit.port is not None", _MISSING_POLICY),
    FeatureSpec("known_shortener", "int",
                 "1 when the hostname belongs to a known URL-shortening service.",
                 "registrable_domain in SHORTENER_DOMAINS", _MISSING_POLICY),
    FeatureSpec("suspicious_keyword_count", "int",
                 "Number of distinct phishing-intent keywords appearing in the URL.",
                 "count of SUSPICIOUS_KEYWORDS present in the lower-cased URL", _MISSING_POLICY),
    FeatureSpec("risky_tld", "int",
                 "1 when the public suffix is in the RISKY_TLDS list.",
                 "suffix in RISKY_TLDS", _MISSING_POLICY),
    FeatureSpec("punycode_hostname", "int",
                 "1 when the hostname contains a punycode ('xn--') label.",
                 "'xn--' in hostname", _MISSING_POLICY),
    FeatureSpec("has_percent_encoding", "int",
                 "1 when the URL contains a percent-escape sequence.",
                 "re.search(r'%[0-9A-Fa-f]{2}', url) is not None", _MISSING_POLICY),
    FeatureSpec("hostname_token_count", "int",
                 "Number of alphanumeric tokens in the hostname.",
                 "split hostname on non-alphanumeric characters", _MISSING_POLICY),
    FeatureSpec("avg_hostname_token_length", "float",
                 "Mean length of the hostname tokens.",
                 "mean token length (0.0 when there are no tokens)", _MISSING_POLICY),
    FeatureSpec("max_token_length", "int",
                 "Longest alphanumeric token anywhere in the URL.",
                 "max token length over the whole URL", _MISSING_POLICY),
    FeatureSpec("brand_mismatch_count", "int",
                 "Number of recognised brand tokens present in the URL whose official "
                 "domain is not the URL's registrable domain (brand impersonation).",
                 "compare BRAND_OFFICIAL_DOMAINS against the registrable domain", _MISSING_POLICY),
    FeatureSpec("num_underscores_total", "int", "Number of '_' characters in the URL.",
                 "normalized_url.count('_')", _MISSING_POLICY),
    FeatureSpec("num_tilde_total", "int", "Number of '~' characters in the URL.",
                 "normalized_url.count('~')", _MISSING_POLICY),
    FeatureSpec("path_depth_ratio", "float",
                 "Path depth relative to URL length (structural depth indicator).",
                 "path_depth / max(url_length, 1)", _MISSING_POLICY),
)

#: Canonical, ordered tuple of feature names -> the model's input vector order.
FEATURE_NAMES: Tuple[str, ...] = tuple(spec.name for spec in FEATURE_SPECS)

#: Index of each feature in the model input vector.
FEATURE_INDEX: Dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}

#: Number of model input features.
NUM_FEATURES = len(FEATURE_NAMES)


def feature_specs_as_dict() -> Dict[str, Dict[str, str]]:
    """Return the full feature dictionary as plain JSON-serialisable data."""
    return {spec.name: spec.as_dict() for spec in FEATURE_SPECS}


def assert_feature_order(features: Tuple[str, ...]) -> None:
    """Guard against accidental re-ordering of the feature vector."""
    if tuple(features) != FEATURE_NAMES:
        raise ValueError(
            "Feature order does not match the canonical schema. "
            f"expected={FEATURE_NAMES} got={tuple(features)}"
        )
