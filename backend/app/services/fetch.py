"""
SSRF-protected HTTP client for optional page-content analysis.

This module is **only** used when ``settings.page_analysis_enabled`` is True.
By default the system operates in URL-only mode, which avoids any outbound
network request during a scan and therefore removes the entire SSRF attack
surface from the core scanning path.

When page analysis is enabled, every fetched URL is:

* validated against the same :mod:`phishguard.url_validation` rules, so the
  destination can only be an ``http``/``https`` URL with a well-formed host;
* resolved via :func:`socket.getaddrinfo` and re-checked against the same
  blocklist before any connection is opened;
* followed with a strict redirect limit, where **every** redirect target is
  re-validated and re-resolved before it is requested (automatic redirect
  following is disabled at the HTTP client level);
* capped by total response size and total request time;
* requested without cookies, authorization headers or any other credentials.

The module never executes downloaded JavaScript and never renders retrieved
HTML as trusted application HTML.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from backend.app.core.config import settings
from phishguard.url_validation import validate_url

logger = logging.getLogger(__name__)


class SsrfBlockedError(Exception):
    """Raised when a destination is blocked by the SSRF policy."""


class FetchTimeoutError(Exception):
    """Raised when a fetch exceeds the configured time budget."""


class FetchTooLargeError(Exception):
    """Raised when the response exceeds the configured byte budget."""


# --------------------------------------------------------------------------
# Address validation
# --------------------------------------------------------------------------

#: Hostnames that must never be fetched (loopback aliases and cloud metadata).
BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
})

#: Private / reserved / loopback / link-local ranges that must never be fetched.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
)


def is_blocked_address(ip_str: str) -> bool:
    """Return True when ``ip_str`` is a blocked (private/reserved) address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not an IP literal -> treat as unsafe rather than guessing.
        return True
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    return any(ip in network for network in PRIVATE_NETWORKS)


def is_blocked_hostname(hostname: str) -> bool:
    """Return True when the hostname itself is on the blocklist."""
    return hostname.lower() in BLOCKED_HOSTNAMES


def resolve_and_check(hostname: str) -> List[str]:
    """Resolve ``hostname`` and reject it if it points at a blocked address.

    Returns the list of resolved IP addresses.  Raises
    :class:`SsrfBlockedError` when *any* resolved address is blocked, which
    prevents DNS round-robin from being used to smuggle in a private address.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfBlockedError(f"Could not resolve hostname '{hostname}': {exc}") from exc

    if not infos:
        raise SsrfBlockedError(f"Hostname '{hostname}' could not be resolved.")

    addresses: List[str] = []
    for info in infos:
        ip_str = info[4][0]
        if is_blocked_address(ip_str):
            raise SsrfBlockedError(
                f"Hostname '{hostname}' resolves to the blocked address '{ip_str}'."
            )
        addresses.append(ip_str)
    return addresses


# --------------------------------------------------------------------------
# Redirect handling
# --------------------------------------------------------------------------


class _NoRedirectHandler(HTTPRedirectHandler):
    """Disable urllib's automatic redirect following.

    Redirects must be validated one hop at a time, so the client is told not
    to follow them and the caller decides what to do with the ``Location``
    header.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


#: Opener that never follows redirects automatically.
_OPENER = build_opener(_NoRedirectHandler)

_USER_AGENT = "PhishGuard-PageAnalysis/1.0 (+https://example.invalid/phishguard)"

#: Headers that are never forwarded to a scanned site.
_STRIPPED_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}


def _build_request(url: str) -> Request:
    """Create a request with no credentials and a fixed user agent."""
    return Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="GET",
    )


def _validate_destination(raw_url: str) -> str:
    """Validate a destination URL against the SSRF policy.

    Returns the normalised URL.  Raises :class:`SsrfBlockedError` when the
    destination is not allowed.
    """
    validated = validate_url(raw_url)

    if validated.scheme not in ("http", "https"):
        raise SsrfBlockedError(f"Scheme '{validated.scheme}' is not allowed for fetching.")

    if is_blocked_hostname(validated.hostname):
        raise SsrfBlockedError(
            f"Hostname '{validated.hostname}' is blocked by the SSRF policy."
        )

    allowed_ports = set(settings.page_analysis_allowed_ports)
    port = validated.port or (443 if validated.scheme == "https" else 80)
    if port not in allowed_ports:
        raise SsrfBlockedError(
            f"Port {port} is not in the allowed port list {sorted(allowed_ports)}."
        )

    resolve_and_check(validated.hostname)
    return validated.normalized_url


def fetch_page_content(
    raw_url: str,
    max_bytes: Optional[int] = None,
    timeout: Optional[float] = None,
    max_redirects: Optional[int] = None,
) -> Dict[str, object]:
    """Fetch the HTML of ``raw_url`` under the SSRF policy.

    Returns a dict with keys ``url``, ``status_code``, ``content_type``,
    ``size_bytes``, ``final_url`` and ``html``.

    Raises
    ------
    SsrfBlockedError
        The destination (or a redirect target) is blocked.
    FetchTimeoutError
        The request exceeded the time budget.
    FetchTooLargeError
        The response exceeded the byte budget.
    """
    if max_bytes is None:
        max_bytes = settings.page_analysis_max_bytes
    if timeout is None:
        timeout = settings.page_analysis_timeout
    if max_redirects is None:
        max_redirects = settings.page_analysis_max_redirects

    started = time.monotonic()
    current_url = _validate_destination(raw_url)
    visited = {current_url}

    for hop in range(max_redirects + 1):
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise FetchTimeoutError(f"Total fetch budget of {timeout}s exceeded.")

        request = _build_request(current_url)
        try:
            with _OPENER.open(request, timeout=remaining) as response:
                status_code = response.getcode()
                content_type = response.headers.get("Content-Type", "")
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise FetchTooLargeError(
                        f"Response exceeded the {max_bytes} byte limit."
                    )
                return {
                    "url": current_url,
                    "final_url": current_url,
                    "status_code": status_code,
                    "content_type": content_type,
                    "size_bytes": len(data),
                    "redirects_followed": hop,
                    "html": data.decode("utf-8", errors="replace"),
                }
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location")
                if not location:
                    raise
                if hop >= max_redirects:
                    raise SsrfBlockedError(
                        f"Exceeded the maximum of {max_redirects} redirects."
                    ) from exc
                next_url = urljoin(current_url, location)
                if next_url in visited:
                    raise SsrfBlockedError("Redirect loop detected.") from exc
                visited.add(next_url)
                # Re-validate and re-resolve the new destination before use.
                current_url = _validate_destination(next_url)
                continue
            raise
        except socket.timeout as exc:
            raise FetchTimeoutError(f"Request timed out: {exc}") from exc
        except URLError as exc:
            if isinstance(exc.reason, socket.timeout):
                raise FetchTimeoutError(f"Request timed out: {exc.reason}") from exc
            raise

    raise SsrfBlockedError(f"Exceeded the maximum of {max_redirects} redirects.")


def analyze_page_content(raw_url: str) -> Dict[str, object]:
    """Fetch and parse the page content, returning structured signals.

    The returned signals are *supplementary evidence*.  They are never fed
    into the machine-learning model, which is trained exclusively on
    URL-lexical features, so a missing or failing fetch can never distort the
    model's prediction.
    """
    result = fetch_page_content(raw_url)
    html = str(result["html"])

    signals: Dict[str, object] = {
        "num_forms": 0,
        "num_password_or_hidden_inputs": 0,
        "num_links": 0,
        "num_scripts": 0,
        "num_iframes": 0,
        "form_submission_destinations": [],
    }

    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        signals["num_forms"] = len(soup.find_all("form"))
        signals["num_password_or_hidden_inputs"] = len(
            soup.find_all("input", attrs={"type": ["password", "hidden"]})
        )
        signals["num_links"] = len(soup.find_all("a", href=True))
        signals["num_scripts"] = len(soup.find_all("script"))
        signals["num_iframes"] = len(soup.find_all("iframe"))

        destinations: List[str] = []
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                destinations.append(action)
        signals["form_submission_destinations"] = destinations[:20]
    except Exception as exc:  # noqa: BLE001 - parsing must never break a scan
        logger.warning("Page parsing failed: %s", exc)
        signals["parse_error"] = str(exc)

    return {
        "fetched": True,
        "url": result["url"],
        "final_url": result["final_url"],
        "status_code": result["status_code"],
        "content_type": result["content_type"],
        "size_bytes": result["size_bytes"],
        "redirects_followed": result["redirects_followed"],
        "signals": signals,
    }
