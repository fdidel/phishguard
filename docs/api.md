# API Reference

Base URL: `http://localhost:8000`

All endpoints return JSON. Error responses use a uniform body shape:

```json
{
  "error": "<error_slug>",
  "message": "Human-readable message",
  "detail": { ... }  // optional, Pydantic validation errors
}
```

HTTP status codes:
- `200` — successful operation
- `404` — resource not found
- `422` — Pydantic body validation error (empty/missing url, overlong url, unknown fields)
- `429` — rate limited

---

## GET /health

Service health probe. Returns status, version, environment, model loaded flag, database connectivity, and feature flags.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "environment": "development",
  "model_loaded": true,
  "model_version": "phishguard-url-rf-1.0.0",
  "database": "ok",
  "page_analysis_enabled": false,
  "threat_intel_enabled": false,
  "timestamp": "2026-10-23T10:00:00Z"
}
```

---

## GET /api/v1/model/info

Returns metadata about the loaded model: availability, version, schema, algorithm, thresholds, feature count, supported features.

**Response:**
```json
{
  "available": true,
  "model_version": "phishguard-url-rf-1.0.0",
  "feature_schema_version": "1.0.0",
  "algorithm": "XGBoost",
  "trained_at": "2026-10-21T18:12:46+00:00",
  "random_seed": 42,
  "thresholds": {
    "suspicious_threshold": 0.625,
    "dangerous_threshold": 0.895,
    "safe_threshold": 0.625
  },
  "feature_count": 35,
  "supported_features": ["uses_https", "url_keyword_count", ...],
  "error": null
}
```

---

## GET /api/v1/model/metrics

Returns the saved evaluation metrics from the held-out test set. This is the **only** source of performance claims — training-set scores are never reported.

**Response includes:** accuracy, precision, recall, F1, FPR, FNR, confusion matrix, feature importance, inference latency, model comparison.

---

## POST /api/v1/scan

Submit a URL for analysis.

**Request body:**
```json
{ "url": "https://paypal.secure-login.example/account/verify?id=99" }
```

**Success response (200):** Full `ScanResult` object:
```json
{
  "scan_id": "scan-uuid",
  "submitted_url": "https://...",
  "normalized_url": "https://...",
  "hostname": "paypal.secure-login.example",
  "registrable_domain": "paypal.secure-login.example",
  "status": "completed",
  "analysis_coverage": "url_only",
  "classification": "dangerous",
  "classification_label": "Dangerous",
  "guidance": "Do not enter credentials or payment details on this site.",
  "risk_score": 91,
  "phishing_probability": 0.97,
  "indicators": [...],
  "explanation": { ... },
  "warnings": [],
  "model_version": "phishguard-url-rf-1.0.0",
  "feature_schema_version": "1.0.0",
  "model_algorithm": "XGBoost",
  "threat_intelligence": null,
  "page_analysis": null,
  "error_code": null,
  "error_message": null,
  "scanned_at": "2026-10-23T10:00:00Z",
  "duration_ms": 12,
  "limitations": ["The model only sees the structure of the address."]
}
```

**Failed scan response (200):** Same shape but `status="failed"`, `classification="unknown"`, `risk_score=null`, `error_code` set, `error_message` set.

**Validation errors (422):** Empty/missing url, overlong url, unknown fields.

---

## GET /api/v1/scans

List scan history with pagination and filtering.

**Query parameters:**
- `page` (int, default 1)
- `page_size` (int, default 20, max 100)
- `status` (filter: completed/inconclusive/failed)
- `classification` (filter: safe/suspicious/dangerous/inconclusive/unknown)
- `domain` (filter by registrable domain substring)
- `q` (full-text search on submitted_url)

**Response:**
```json
{
  "items": [
    {
      "scan_id": "uuid",
      "submitted_url": "https://...",
      "normalized_url": "https://...",
      "hostname": "...",
      "status": "completed",
      "classification": "dangerous",
      "risk_score": 91,
      "phishing_probability": 0.97,
      "model_version": "phishguard-url-rf-1.0.0",
      "scanned_at": "2026-10-23T10:00:00Z",
      "duration_ms": 12
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20,
  "pages": 3
}
```

---

## GET /api/v1/scans/{scan_id}

Full detail of a single scan. Returns the complete `ScanDetail` object including indicators, explanation, warnings, and error fields.

---

## POST /api/v1/feedback

Submit feedback for a scan to improve the model.

**Request body:**
```json
{
  "scan_id": "uuid",
  "is_correct": true,
  "correct_classification": "safe",   // optional
  "comment": "This was a legitimate login page."  // optional
}
```

**Response:** `{ "recorded": true }` or `{ "recorded": false, "error": "not_found" }`

---

## GET /api/v1/reports/summary

Aggregate statistics across all scan history.

**Response:**
```json
{
  "total_scans": 42,
  "by_status": { "completed": 38, "failed": 4, "inconclusive": 0 },
  "by_classification": { "safe": 20, "suspicious": 5, "dangerous": 10, "inconclusive": 3, "unknown": 4 },
  "average_risk_score": 67.5,
  "dangerous_scans": 10,
  "suspicious_scans": 5,
  "safe_scans": 20,
  "failed_scans": 4,
  "unique_domains": 15,
  "generated_at": "2026-10-23T10:00:00Z"
}
```

---

## GET /api/v1/reports/export

Export scan history as CSV. Credentials in URLs are redacted.

**Query parameters:**
- `limit` (int, default 1000, max 10000)

**Response:** `text/csv` stream with header row and one row per scan.
