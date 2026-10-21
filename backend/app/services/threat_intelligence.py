"""
Optional threat-intelligence integration.

The system never *depends* on a blacklist.  Threat intelligence is an
optional, configurable supplement:

* ``none`` (default) - no lookup at all; the core application works fully
  offline with no API key.
* ``local`` - reads a local newline-delimited file of known malicious URLs or
  domains.  No network traffic, no third-party disclosure.
* ``http`` - queries a configured HTTP service.  Disabled unless the operator
  explicitly sets ``THREAT_INTEL_ALLOW_EXTERNAL_LOOKUP=true``, because it
  transmits the submitted URL to a third party.

Every provider returns a :class:`ThreatIntelResult` that records whether the
lookup actually succeeded.  A failed or unavailable lookup is reported as
``unavailable`` and is **never** interpreted as evidence that a site is safe.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol

from backend.app.core.config import settings
from phishguard.url_validation import validate_url

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Outcome of a threat-intelligence lookup."""

    #: True only when the lookup completed and the URL was found on a list.
    listed: bool = False
    #: "match", "not_found" or "unavailable".
    status: str = "unavailable"
    #: Name of the provider that produced the result.
    provider: str = "none"
    #: Source (URL/file) of the intelligence feed.
    source: Optional[str] = None
    #: Timestamp of the successful lookup (ISO-8601, UTC).
    looked_up_at: Optional[str] = None
    #: Human-readable note.
    detail: Optional[str] = None
    #: Extra provider-specific data.
    extra: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "listed": self.listed,
            "status": self.status,
            "provider": self.provider,
            "source": self.source,
            "looked_up_at": self.looked_up_at,
            "detail": self.detail,
            "extra": self.extra,
        }


class ThreatIntelProvider(Protocol):
    """Interface implemented by every threat-intelligence provider."""

    name: str

    def lookup(self, normalized_url: str, hostname: str) -> ThreatIntelResult:
        """Look the URL up and return the result."""
        ...


class NullThreatIntelProvider:
    """Provider used when threat intelligence is disabled."""

    name = "none"

    def lookup(self, normalized_url: str, hostname: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            listed=False,
            status="disabled",
            provider=self.name,
            detail="Threat intelligence is disabled; no external lookup was performed.",
        )


class LocalBlacklistProvider:
    """Provider backed by a local file of malicious URLs / domains.

    The file is expected to contain one entry per line.  Lines may be full
    URLs or bare hostnames.  Blank lines and ``#`` comments are ignored.
    """

    name = "local"

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or settings.threat_intel_blacklist_path
        self._entries: Optional[set] = None
        self._loaded_at: Optional[str] = None

    def _load(self) -> set:
        if self._entries is not None:
            return self._entries
        entries: set = set()
        if self.path and os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        entries.add(line.lower())
                        # Also index the bare hostname of full URLs.
                        if "://" in line:
                            try:
                                entries.add(validate_url(line).hostname.lower())
                            except Exception:
                                pass
            except OSError as exc:
                logger.warning("Could not read local blacklist: %s", exc)
        self._entries = entries
        from datetime import datetime, timezone

        self._loaded_at = datetime.now(timezone.utc).isoformat()
        return entries

    def lookup(self, normalized_url: str, hostname: str) -> ThreatIntelResult:
        from datetime import datetime, timezone

        if not self.path:
            return ThreatIntelResult(
                listed=False,
                status="unavailable",
                provider=self.name,
                detail="No local blacklist file is configured.",
            )
        if not os.path.exists(self.path):
            return ThreatIntelResult(
                listed=False,
                status="unavailable",
                provider=self.name,
                source=self.path,
                detail="The configured local blacklist file does not exist.",
            )

        entries = self._load()
        lowered = normalized_url.lower()
        listed = lowered in entries or hostname.lower() in entries

        return ThreatIntelResult(
            listed=listed,
            status="match" if listed else "not_found",
            provider=self.name,
            source=self.path,
            looked_up_at=datetime.now(timezone.utc).isoformat(),
            detail=(
                "The URL appears on the local malicious-URL list."
                if listed
                else "The URL was not found on the local malicious-URL list."
            ),
            extra={"entries": len(entries)},
        )


class HttpThreatIntelProvider:
    """Provider that queries an external HTTP threat-intelligence service.

    Disabled unless ``threat_intel_allow_external_lookup`` is explicitly set,
    because a lookup transmits the submitted URL to a third party.
    """

    name = "http"

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = (base_url or os.getenv("THREAT_INTEL_BASE_URL", "")).rstrip("/")

    def lookup(self, normalized_url: str, hostname: str) -> ThreatIntelResult:
        from datetime import datetime, timezone

        if not settings.threat_intel_allow_external_lookup:
            return ThreatIntelResult(
                listed=False,
                status="unavailable",
                provider=self.name,
                detail=(
                    "External threat-intelligence lookups are disabled. Set "
                    "THREAT_INTEL_ALLOW_EXTERNAL_LOOKUP=true and THREAT_INTEL_BASE_URL "
                    "to enable them (this sends the submitted URL to a third party)."
                ),
            )
        if not self.base_url:
            return ThreatIntelResult(
                listed=False,
                status="unavailable",
                provider=self.name,
                detail="No external threat-intelligence endpoint is configured.",
            )

        try:
            import httpx

            with httpx.Client(timeout=settings.threat_intel_timeout, follow_redirects=False) as client:
                response = client.get(
                    f"{self.base_url}/lookup", params={"url": normalized_url}
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001 - provider failures must not break a scan
            logger.warning("External threat-intelligence lookup failed: %s", exc)
            return ThreatIntelResult(
                listed=False,
                status="unavailable",
                provider=self.name,
                source=self.base_url,
                detail=f"The threat-intelligence service could not be reached: {exc}",
            )

        listed = bool(payload.get("listed", False))
        return ThreatIntelResult(
            listed=listed,
            status="match" if listed else "not_found",
            provider=self.name,
            source=self.base_url,
            looked_up_at=datetime.now(timezone.utc).isoformat(),
            detail=payload.get("detail"),
            extra={"raw": payload},
        )


def build_provider() -> ThreatIntelProvider:
    """Instantiate the configured provider."""
    if not settings.threat_intel_enabled:
        return NullThreatIntelProvider()

    provider = (settings.threat_intel_provider or "none").lower()
    if provider == "local":
        return LocalBlacklistProvider()
    if provider == "http":
        return HttpThreatIntelProvider()
    logger.warning(
        "Unknown threat-intelligence provider '%s'; falling back to 'none'.", provider
    )
    return NullThreatIntelProvider()


def lookup(normalized_url: str, hostname: str) -> ThreatIntelResult:
    """Run a threat-intelligence lookup with the configured provider."""
    provider = build_provider()
    try:
        return provider.lookup(normalized_url, hostname)
    except Exception as exc:  # noqa: BLE001 - never let a provider break a scan
        logger.exception("Threat-intelligence lookup failed: %s", exc)
        return ThreatIntelResult(
            listed=False,
            status="unavailable",
            provider=getattr(provider, "name", "unknown"),
            detail=f"The threat-intelligence lookup failed: {exc}",
        )
