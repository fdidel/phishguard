"""
URL validation and normalisation.

This module is deliberately dependency-free (stdlib only) so that it can be
used safely inside the sandboxed fetch layer and in the offline training
pipeline alike.

Policy summary (documented in docs/architecture.md)
----------------------------------------------------
* Only ``http`` and ``https`` are accepted.  Every other scheme is rejected
  with ``UNSUPPORTED_SCHEME`` (this blocks ``file:``, ``gopher:``, ``data:``,
  ``javascript:`` and friends).
* A URL submitted without a scheme is normalised by prepending ``https://``
  and is flagged with ``scheme_inferred=True``.  The *original* input is
  always preserved for reporting.
* The hostname is obtained from :func:`urllib.parse.urlsplit` - never with
  substring splitting - so userinfo (``user@host``), ports, IPv6 literals and
  percent-encoded hosts are handled correctly.
* Malformed input raises :class:`UrlValidationError`; it never raises an
  unhandled exception and never produces a partial/garbled host.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

#: Maximum accepted length of the submitted URL string.
MAX_URL_LENGTH = 2048

#: Maximum accepted length of the hostname.
MAX_HOSTNAME_LENGTH = 253

#: Maximum accepted length of a single DNS label.
MAX_LABEL_LENGTH = 63

#: Schemes the system is willing to analyse.
ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")

#: Scheme assumed when the user omits one.
DEFAULT_SCHEME = "https"

# Hostname grammar: labels of [a-z0-9-], separated by dots.  Punycode
# labels (xn--...) satisfy the same grammar.
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# A scheme is only considered present when it is followed by '://'.
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")

# A leading "word:" with no '//' is treated as an unsupported scheme
# (e.g. "mailto:a@b.com", "javascript:alert(1)", "data:text/html,...").
_OPAQUE_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(?!\d)")

# Characters that must never appear raw inside a URL.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x20\x7f]")


class UrlValidationError(ValueError):
    """Raised when a submitted URL cannot be validated.

    The ``code`` attribute is a stable machine-readable identifier that the API
    layer maps onto an HTTP status code and a user-facing message.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"UrlValidationError(code={self.code!r}, message={self.message!r})"


@dataclass(frozen=True)
class ValidatedUrl:
    """The result of successfully validating and normalising a URL."""

    original_input: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    subdomain: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    scheme_inferred: bool
    has_userinfo: bool
    is_ip_host: bool
    is_ipv6: bool
    host_labels: Tuple[str, ...] = field(default=())

    @property
    def host_for_display(self) -> str:
        """Hostname shown to the user (IPv6 literals keep their brackets)."""
        if self.is_ipv6:
            return f"[{self.hostname}]"
        return self.hostname

    @property
    def effective_host(self) -> str:
        """Hostname including an explicit port, if any."""
        if self.port is not None:
            return f"{self.host_for_display}:{self.port}"
        return self.host_for_display


# --------------------------------------------------------------------------
# Public-suffix handling
# --------------------------------------------------------------------------

try:  # pragma: no cover - exercised implicitly
    import tldextract

    # suffix_list_urls=() => never touch the network; use the bundled snapshot.
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover - fallback when tldextract is unavailable
    _TLD_EXTRACT = None

#: Small fallback used only if tldextract cannot be imported.
_FALLBACK_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za",
    "com.br", "com.mx", "com.ar", "com.cn", "com.tr", "com.sg", "com.hk",
    "co.in", "net.in", "org.in", "co.kr", "or.kr",
    "com.ng", "org.ng", "gov.ng", "edu.ng",
    "com.gh", "edu.gh", "gov.gh",
}


def _fallback_registrable_domain(hostname: str) -> Tuple[str, str]:
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname, ""
    tail2 = ".".join(labels[-2:])
    if tail2 in _FALLBACK_MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:]), ".".join(labels[:-3])
    return tail2, ".".join(labels[:-2])


def split_registrable_domain(hostname: str) -> Tuple[str, str]:
    """Return ``(registrable_domain, subdomain)`` for a lower-cased hostname.

    ``registrable_domain`` is the "public suffix + 1" label, e.g.
    ``login.paypal.co.uk`` -> ``(paypal.co.uk, "login")``.
    """
    if not hostname or _TLD_EXTRACT is None:
        return _fallback_registrable_domain(hostname) if hostname else ("", "")

    extracted = _TLD_EXTRACT(hostname)
    if not extracted.domain or not extracted.suffix:
        # Host is a bare label such as "localhost" or an IP literal.
        return (hostname, "")
    registrable = f"{extracted.domain}.{extracted.suffix}"
    subdomain = extracted.subdomain or ""
    return (registrable, subdomain)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def _check_hostname(hostname: str) -> None:
    """Validate hostname grammar; raises :class:`UrlValidationError`."""
    if not hostname:
        raise UrlValidationError("INVALID_HOST", "The URL does not contain a valid hostname.")

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise UrlValidationError(
            "INVALID_HOST", f"Hostname exceeds {MAX_HOSTNAME_LENGTH} characters."
        )

    # IP literals (v4 / v6) are allowed through the grammar check.
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass

    if hostname.endswith("."):
        hostname = hostname[:-1]

    labels = hostname.split(".")
    for label in labels:
        if not label:
            raise UrlValidationError(
                "INVALID_HOST", "The hostname contains an empty label."
            )
        if len(label) > MAX_LABEL_LENGTH:
            raise UrlValidationError(
                "INVALID_HOST", f"Hostname label '{label[:20]}...' is too long."
            )
        if not _HOSTNAME_LABEL_RE.match(label):
            raise UrlValidationError(
                "INVALID_HOST",
                "The hostname contains characters that are not permitted in a DNS name.",
            )


def _to_ascii_hostname(hostname: str) -> str:
    """Convert a unicode host to its IDNA (punycode) form, best effort."""
    if hostname.isascii():
        return hostname
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except Exception:
        raise UrlValidationError(
            "INVALID_HOST", "The hostname contains an invalid international domain name."
        )


def validate_url(raw_url: str) -> ValidatedUrl:
    """Validate and normalise a submitted URL.

    Raises
    ------
    UrlValidationError
        If the input cannot be parsed into an analysable HTTP(S) URL.
    """
    if raw_url is None:
        raise UrlValidationError("EMPTY_URL", "No URL was submitted.")

    if not isinstance(raw_url, str):
        raise UrlValidationError("INVALID_URL", "The URL must be a string.")

    original = raw_url
    candidate = raw_url.strip()

    if not candidate:
        raise UrlValidationError("EMPTY_URL", "No URL was submitted.")

    if len(candidate) > MAX_URL_LENGTH:
        raise UrlValidationError(
            "URL_TOO_LONG",
            f"The URL exceeds the maximum supported length of {MAX_URL_LENGTH} characters.",
        )

    if "\\" in candidate:
        raise UrlValidationError(
            "INVALID_CHARACTERS",
            "Backslashes are not permitted in URLs and are often used to confuse parsers.",
        )

    if _CONTROL_CHARS_RE.search(candidate):
        raise UrlValidationError(
            "INVALID_CHARACTERS",
            "The URL contains whitespace or control characters.",
        )

    scheme_inferred = False
    match = _SCHEME_RE.match(candidate)
    if match:
        scheme = match.group(1).lower()
        if scheme not in ALLOWED_SCHEMES:
            raise UrlValidationError(
                "UNSUPPORTED_SCHEME",
                f"Only http and https URLs can be analysed (received '{scheme}').",
            )
    else:
        opaque = _OPAQUE_SCHEME_RE.match(candidate)
        if opaque:
            scheme = opaque.group(1).lower()
            raise UrlValidationError(
                "UNSUPPORTED_SCHEME",
                f"Only http and https URLs can be analysed (received '{scheme}').",
            )
        scheme = DEFAULT_SCHEME
        scheme_inferred = True
        candidate = f"{scheme}://{candidate.lstrip('/')}"

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:  # pragma: no cover - urlsplit rarely raises
        raise UrlValidationError("INVALID_URL", f"The URL could not be parsed: {exc}")

    try:
        port = parts.port  # raises ValueError for out-of-range / non-numeric ports
    except ValueError:
        raise UrlValidationError("INVALID_PORT", "The URL contains an invalid port number.")

    if port is not None and not (1 <= port <= 65535):
        raise UrlValidationError("INVALID_PORT", "The URL contains an invalid port number.")

    try:
        hostname = parts.hostname  # type: ignore[assignment]
    except ValueError:
        raise UrlValidationError("INVALID_HOST", "The URL contains an invalid hostname.")

    if not hostname:
        raise UrlValidationError("INVALID_HOST", "The URL does not contain a valid hostname.")

    hostname = hostname.strip().rstrip(".")
    hostname = _to_ascii_hostname(hostname)
    _check_hostname(hostname)

    has_userinfo = parts.username is not None or "@" in parts.netloc
    is_ipv6 = False
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        is_ipv6 = ip_obj.version == 6
    except ValueError:
        pass

    registrable_domain, subdomain = split_registrable_domain(hostname)

    netloc = hostname
    if is_ipv6:
        netloc = f"[{hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = parts.path or ""
    query = parts.query or ""
    fragment = parts.fragment or ""

    normalized_url = urlunsplit((scheme, netloc, path, query, fragment))

    host_labels = tuple(label for label in hostname.split(".") if label)

    return ValidatedUrl(
        original_input=original,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        registrable_domain=registrable_domain,
        subdomain=subdomain,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        scheme_inferred=scheme_inferred,
        has_userinfo=has_userinfo,
        is_ip_host=is_ip,
        is_ipv6=is_ipv6,
        host_labels=host_labels,
    )


def normalize_url(raw_url: str) -> str:
    """Convenience wrapper returning only the normalised URL string."""
    return validate_url(raw_url).normalized_url


def is_valid_url(raw_url: str) -> bool:
    """Return ``True`` when the URL passes validation."""
    try:
        validate_url(raw_url)
        return True
    except UrlValidationError:
        return False
