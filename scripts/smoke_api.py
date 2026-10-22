"""End-to-end smoke test for the PhishGuard API.

Run with::

    python scripts/smoke_api.py

The script exercises every public endpoint against the trained model artifact
and prints the observed responses.  It is a manual verification helper; the
automated equivalents live in ``backend/tests/``.
"""

from __future__ import annotations

import json
import os
import sys

# Configure an isolated database *before* the application modules are imported.
os.environ.setdefault("DATABASE_URL", "sqlite:///./smoke_test.db")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("PAGE_ANALYSIS_ENABLED", "false")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.main import app  # noqa: E402

LEGITIMATE_URLS = [
    "https://www.google.com/search?q=phishing",
    "https://github.com/python/cpython",
    "https://en.wikipedia.org/wiki/Phishing",
]

PHISHING_URLS = [
    "http://paypal-secure-login.verify-account.top/auth/login?cmd=_account-update",
    "https://secure-appleid.apple.com.verify.evil.co/signin",
    "http://192.168.0.1:8080/router/login.htm",
]

MALFORMED_URLS = [
    "javascript:alert(document.cookie)",
    "not a url at all",
    "http://",
    "",
]


def show(title: str, payload: object) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")
    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2, default=str)[:2600])
    else:
        print(payload)


def main() -> int:
    failures = []

    with TestClient(app) as client:
        # -- health -----------------------------------------------------
        response = client.get("/health")
        show("GET /health", response.json())
        if response.status_code != 200:
            failures.append("GET /health did not return 200")
        if not response.json().get("model_loaded"):
            failures.append("model was not loaded at start-up")

        # -- model info ------------------------------------------------
        response = client.get("/api/v1/model/info")
        show("GET /api/v1/model/info", response.json())
        if response.status_code != 200:
            failures.append("GET /api/v1/model/info did not return 200")

        # -- model metrics ----------------------------------------------
        response = client.get("/api/v1/model/metrics")
        metrics = response.json()
        show(
            "GET /api/v1/model/metrics (test_set)",
            metrics.get("test_set", metrics) if isinstance(metrics, dict) else metrics,
        )
        if response.status_code != 200:
            failures.append("GET /api/v1/model/metrics did not return 200")

        # -- scans: legitimate ------------------------------------------
        for url in LEGITIMATE_URLS:
            response = client.post("/api/v1/scan", json={"url": url})
            body = response.json()
            show(
                f"POST /api/v1/scan  [{body.get('classification')}]",
                {
                    "url": url,
                    "status": body.get("status"),
                    "classification": body.get("classification"),
                    "classification_label": body.get("classification_label"),
                    "risk_score": body.get("risk_score"),
                    "phishing_probability": body.get("phishing_probability"),
                    "guidance": body.get("guidance"),
                    "indicators": body.get("indicators"),
                    "model_version": body.get("model_version"),
                    "duration_ms": body.get("duration_ms"),
                },
            )
            if response.status_code != 200:
                failures.append(f"scan of {url} returned {response.status_code}")

        # -- scans: phishing ---------------------------------------------
        for url in PHISHING_URLS:
            response = client.post("/api/v1/scan", json={"url": url})
            body = response.json()
            show(
                f"POST /api/v1/scan  [{body.get('classification')}]",
                {
                    "url": url,
                    "status": body.get("status"),
                    "classification": body.get("classification"),
                    "classification_label": body.get("classification_label"),
                    "risk_score": body.get("risk_score"),
                    "phishing_probability": body.get("phishing_probability"),
                    "guidance": body.get("guidance"),
                    "indicators": body.get("indicators"),
                },
            )
            if body.get("classification") == "safe":
                failures.append(f"phishing URL {url} was classified as safe")

        # -- scans: malformed --------------------------------------------
        for url in MALFORMED_URLS:
            response = client.post("/api/v1/scan", json={"url": url})
            body = response.json()
            show(
                f"POST /api/v1/scan (malformed) [{body.get('classification')}]",
                {
                    "url": url,
                    "status_code": response.status_code,
                    "status": body.get("status"),
                    "classification": body.get("classification"),
                    "error_code": body.get("error_code"),
                    "error_message": body.get("error_message"),
                },
            )
            if body.get("classification") == "safe":
                failures.append(f"malformed URL {url} was classified as safe")
            # Two rejection paths are acceptable and neither may report "safe":
            #   * 422 - the request schema rejected the payload before scanning;
            #   * 200 with status="failed" - the scan ran and could not analyse
            #     the URL (classification is "unknown", never "safe").
            if response.status_code == 422:
                if "detail" not in body and "error" not in body:
                    failures.append(f"422 response for {url!r} had no error detail")
            elif body.get("status") != "failed":
                failures.append(
                    f"malformed URL {url!r} did not produce a failed status "
                    f"(status={body.get('status')!r}, code={response.status_code})"
                )

        # -- history ------------------------------------------------------
        response = client.get("/api/v1/scans", params={"page": 1, "page_size": 5})
        history = response.json()
        show(
            "GET /api/v1/scans",
            {
                "total": history.get("total"),
                "page": history.get("page"),
                "page_size": history.get("page_size"),
                "pages": history.get("pages"),
                "first_item": (history.get("items") or [{}])[0],
            },
        )
        if response.status_code != 200:
            failures.append("GET /api/v1/scans did not return 200")

        items = history.get("items") or []
        if items:
            scan_id = items[0]["scan_id"]
            response = client.get(f"/api/v1/scans/{scan_id}")
            show(f"GET /api/v1/scans/{scan_id}", response.json())
            if response.status_code != 200:
                failures.append("GET /api/v1/scans/{id} did not return 200")

            # -- feedback -------------------------------------------------
            response = client.post(
                "/api/v1/feedback",
                json={"scan_id": scan_id, "is_correct": True},
            )
            show("POST /api/v1/feedback", response.json())
            if response.status_code not in (200, 201):
                failures.append("POST /api/v1/feedback did not return 200/201")

        # -- 404 ----------------------------------------------------------
        response = client.get("/api/v1/scans/does-not-exist")
        show("GET /api/v1/scans/does-not-exist", {"status_code": response.status_code})
        if response.status_code != 404:
            failures.append("unknown scan id did not return 404")

        # -- reports -------------------------------------------------------
        response = client.get("/api/v1/reports/summary")
        show("GET /api/v1/reports/summary", response.json())
        if response.status_code != 200:
            failures.append("GET /api/v1/reports/summary did not return 200")

        response = client.get("/api/v1/reports/export.csv")
        print(f"\n{'=' * 78}\nGET /api/v1/reports/export.csv\n{'=' * 78}")
        print(response.text[:900])
        if response.status_code != 200:
            failures.append("CSV export did not return 200")

        # -- security headers ---------------------------------------------
        response = client.get("/health")
        print("\nSecurity headers:")
        for key in (
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "content-security-policy",
            "cache-control",
        ):
            print(f"  {key}: {response.headers.get(key)}")

        # -- openapi --------------------------------------------------------
        response = client.get("/openapi.json")
        paths = sorted(response.json().get("paths", {}).keys())
        print(f"\nOpenAPI paths ({response.status_code}):")
        for path in paths:
            print(f"  {path}")

    print(f"\n{'=' * 78}")
    if failures:
        print("SMOKE FAILED - issues detected:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("SMOKE_OK - all endpoints behaved as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
