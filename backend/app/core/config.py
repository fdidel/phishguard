"""Application configuration (environment-driven)."""

from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the PhishGuard API.

    Every value can be overridden with an environment variable of the same
    name (case-insensitive).  See ``.env.example`` for the full list.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Application ----------------------------------------------------
    app_name: str = "PhishGuard API"
    app_version: str = "1.0.0"
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # -- Database -------------------------------------------------------
    database_url: str = Field(default="sqlite:///./phishguard.db")

    # -- Model ----------------------------------------------------------
    model_path: str = Field(default="ml/artifacts/phishguard_model.joblib")
    metrics_path: str = Field(default="ml/artifacts/model_metrics.json")
    model_artifact_dir: str = Field(default="ml/artifacts")

    # -- Security -------------------------------------------------------
    cors_allow_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
        ]
    )
    #: Master switch for the per-IP rate limiter.  Disabled only in tests.
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=30, ge=1)
    max_url_length: int = Field(default=2048, ge=64, le=8192)

    # -- Optional page analysis (SSRF-protected) ------------------------
    page_analysis_enabled: bool = Field(default=False)
    page_analysis_timeout: float = Field(default=5.0, gt=0, le=60)
    page_analysis_max_bytes: int = Field(default=512 * 1024, ge=1024)
    page_analysis_max_redirects: int = Field(default=3, ge=0, le=10)
    page_analysis_allowed_ports: List[int] = Field(default_factory=lambda: [80, 443])
    page_analysis_allow_private_hosts: bool = Field(default=False)

    # -- Optional threat intelligence -----------------------------------
    threat_intel_enabled: bool = Field(default=False)
    threat_intel_provider: str = Field(default="none")
    threat_intel_blacklist_path: str = Field(default="")
    threat_intel_timeout: float = Field(default=5.0, gt=0, le=60)
    #: Explicit opt-in required before a submitted URL is sent to a
    #: third-party threat-intelligence service.
    threat_intel_allow_external_lookup: bool = Field(default=False)

    # -- Retention ------------------------------------------------------
    scan_retention_days: int = Field(default=90, ge=1)

    @field_validator("cors_allow_origins", "page_analysis_allowed_ports", mode="before")
    @classmethod
    def _split_csv(cls, value):
        """Allow comma-separated values in environment variables."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def database_path(self) -> Optional[str]:
        """Filesystem path of the SQLite database (None for other engines)."""
        if self.database_url.startswith("sqlite:///"):
            return self.database_url.replace("sqlite:///", "", 1)
        return None


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()


settings = get_settings()
