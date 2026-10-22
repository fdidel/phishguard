"""FastAPI application factory for the PhishGuard API.

The module exposes a ready-to-serve ``app`` object::

    uvicorn backend.app.main:app --reload

Responsibilities of this module:

* wire the API routers,
* apply CORS from the environment,
* add security headers to every response,
* enforce a per-IP rate limit,
* translate unexpected exceptions into safe, uniform error bodies (never a
  stack trace in production),
* load the ML model and initialise the database at start-up.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Awaitable, Callable, Dict, List

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from backend.app.core.config import settings
from backend.app.database.base import init_db
from backend.app.services.classifier import model_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")

#: Length of the rate-limiting window in seconds.
RATE_LIMIT_WINDOW_SECONDS = 60

#: In-memory sliding-window state: client key -> list of request timestamps.
_RATE_STORE: Dict[str, List[float]] = {}


def _client_key(request: Request) -> str:
    """Return the rate-limiting key for a request.

    The direct peer address is used.  ``X-Forwarded-For`` is deliberately
    *not* trusted unless the deployment sits behind a known proxy, because a
    client-supplied header would otherwise let an attacker bypass the limit.
    """
    if request.client is not None and request.client.host:
        return request.client.host
    return "anonymous"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding-window rate limiter.

    The limiter is intentionally simple and in-process: it protects a single
    API instance from accidental (or deliberate) request floods without
    requiring an external Redis dependency.  A multi-instance deployment
    should place a shared limiter in front of the service.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Never rate-limit the health probe or the interactive docs.
        if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"}:
            return await call_next(request)

        key = _client_key(request)
        now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS

        hits = _RATE_STORE.get(key)
        if hits is None:
            hits = []
            _RATE_STORE[key] = hits
        hits[:] = [stamp for stamp in hits if stamp > cutoff]

        if len(hits) >= settings.rate_limit_per_minute:
            retry_after = int(
                RATE_LIMIT_WINDOW_SECONDS - (now - hits[0]) + 1
            )
            logger.warning("Rate limit hit for client %s", key)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limited",
                    "message": (
                        f"Too many requests. The limit is "
                        f"{settings.rate_limit_per_minute} requests per minute. "
                        f"Please retry in {retry_after} seconds."
                    ),
                },
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        hits.append(now)
        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach conservative security headers to every response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Load the ML model and initialise the database at start-up."""
    logger.info("Starting %s %s", settings.app_name, settings.app_version)

    if model_service.load():
        logger.info("Model ready: %s", model_service.info().get("model_version"))
    else:
        # A missing model must not stop the API from booting: the scan
        # endpoint then answers with an explicit "analysis failed" result
        # instead of a fabricated verdict.
        logger.error("Model unavailable: %s", model_service.load_error)

    try:
        init_db()
    except Exception:  # noqa: BLE001 - the health probe reports database errors
        logger.exception("Database initialisation failed")

    yield
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "AI-powered phishing URL detection and website safety verification.\n\n"
            "The service returns a **SAFE**, **SUSPICIOUS**, **DANGEROUS** or "
            "**INCONCLUSIVE** verdict together with the evidence behind it. "
            "A verdict is an automated assessment, never a guarantee that a "
            "site is safe."
        ),
        contact={
            "name": "BSc Computer Science Project - Nasarawa State University, Keffi",
        },
        license_info={"name": "MIT"},
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept", "Authorization"],
        max_age=600,
    )
    # Middleware runs bottom-up, so the rate limiter is added last to make it
    # the outermost layer (it should reject a flood before any work is done).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)

    from backend.app.api import feedback, health, model, reports, scan, scans

    app.include_router(health.router)
    app.include_router(model.router)
    app.include_router(scan.router)
    app.include_router(scans.router)
    app.include_router(feedback.router)
    app.include_router(reports.router)

    # -- Error handlers -------------------------------------------------
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return a uniform 422 body for request-validation failures."""
        logger.info("Validation error on %s: %s", request.url.path, exc.errors())
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_error",
                "message": "The request body or query parameters are invalid.",
                "detail": _safe_errors(exc.errors()),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Return a uniform error body for HTTP errors."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": _error_slug(exc.status_code),
                "message": str(exc.detail),
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Catch-all handler.

        The traceback is written to the server log only; the client receives a
        generic message so that internal paths and stack details are never
        leaked.
        """
        logger.exception(
            "Unhandled exception on %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": (
                    "An unexpected error occurred while processing the request. "
                    "The problem has been recorded in the server log."
                ),
            },
        )

    return app


def _safe_errors(errors: List[Dict]) -> List[Dict]:
    """Strip non-serialisable context out of pydantic error dictionaries."""
    cleaned = []
    for error in errors:
        item = {
            "location": [str(part) for part in error.get("loc", ())],
            "message": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        cleaned.append(item)
    return cleaned


def _error_slug(status_code: int) -> str:
    """Map an HTTP status code onto a stable machine-readable slug."""
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        413: "payload_too_large",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        503: "service_unavailable",
    }.get(status_code, "error")


#: Application instance used by ``uvicorn backend.app.main:app``.
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.debug,
    )
