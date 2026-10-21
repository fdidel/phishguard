"""Ad-hoc smoke test for the phishguard core package (not part of the test suite)."""
import sys

from phishguard.feature_extraction import extract_features_from_url
from phishguard.feature_schema import FEATURE_NAMES
from phishguard.url_validation import UrlValidationError, validate_url

CASES = [
    "http://guiadebelezadejpa.com/Paypal_Virefication/5486ecddcd98d85e4a24ab714e60257d/",
    "https://www.actionagainsthunger.org/story/empowering-mothers",
    "http://192.168.1.1/login",
    "http://user@evil.example.com/",
    "example.com",
    "https://paypal.secure-login.evil.tk/verify?session=abc",
    "http://[2001:db8::1]/x",
    "https://xn--80ak6aa92e.com/",
    "https://www.google.com/search?q=test&lang=en",
    "http://host.sk/faq/",
]

print("NUM_FEATURES =", len(FEATURE_NAMES))
for case in CASES:
    v = validate_url(case)
    f = extract_features_from_url(case)
    assert set(f) == set(FEATURE_NAMES), "feature mismatch"
    print(
        f"{case[:52]:<54} host={v.host_for_display:<32} reg={v.registrable_domain:<22} "
        f"sub={v.subdomain:<12} brand={int(f['brand_mismatch_count'])} "
        f"kw={int(f['suspicious_keyword_count'])} ip={int(f['has_ip_address'])} "
        f"at={int(f['has_at_symbol'])} https={int(f['uses_https'])}"
    )

BAD = [
    "",
    "   ",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "data:text/html,<script>alert(1)</script>",
    "mailto:someone@example.com",
    "ftp://example.com",
    "http://exa mple.com",
    "http://example.com\\@evil.com",
    "http://" + "a" * 3000 + ".com",
    "http://example..com",
    "http://-bad-.com",
]
print("\n--- rejection tests ---")
for case in BAD:
    try:
        validate_url(case)
        print(f"  NOT REJECTED (!!): {case[:60]!r}")
        sys.exit(1)
    except UrlValidationError as exc:
        print(f"  rejected {case[:40]!r:<44} -> {exc.code}")

print("\nSMOKE_OK")
