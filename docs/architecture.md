# Architecture

## Overview

PhishGuard is an AI-powered phishing URL detection and website safety verification system. It accepts a submitted URL, extracts 35 lexical features from the URL structure, classifies it as SAFE / SUSPICIOUS / DANGEROUS / INCONCLUSIVE using an XGBoost classifier wrapped in a calibrated ensemble, and returns a human-readable verdict with evidence.

The system follows a **Design Science Research** approach under **Pragmatism**, implemented via the **Waterfall Model** with seven phases. The architecture is split into three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React + TypeScript + Vite)                       │
│  ScanForm → ScanResultPanel → ScanHistoryTable               │
│  ModelInfoPanel                                              │
└──────────────────────────┬──────────────────────────────────┘
                          │ REST API (JSON)
┌──────────────────────────▼──────────────────────────────────┐
│  Backend (FastAPI + Pydantic v2 + SQLAlchemy 2.0)           │
│  POST /api/v1/scan                                          │
│  GET  /api/v1/scans                                        │
│  GET  /api/v1/scans/{id}                                   │
│  GET  /api/v1/reports/summary                              │
│  GET  /api/v1/reports/export                               │
│  GET  /health                                                │
│  GET  /api/v1/model/info                                   │
│  GET  /api/v1/model/metrics                                │
│  POST /api/v1/feedback                                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Shared Package (phishguard/)                               │
│  url_validation.py  →  ValidatedUrl dataclass                │
│  feature_extraction.py → 35 lexical features                 │
│  feature_schema.py    → schema version + feature names      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  ML Pipeline (ml/src/)                                       │
│  ingestion.py  →  load dataset                               │
│  preprocessing.py → clean + extract features                │
│  train.py      →  XGBoost + CalibratedClassifierCV          │
│  evaluate.py    →  held-out test metrics                     │
└─────────────────────────────────────────────────────────────┘
```

## Component Map

| Module | Component | Responsibility |
|--------|-----------|---------------|
| A | UI Dashboard | React SPA: scan form, result panel, history table, model info |
| B | URL Validation & Normalization | `phishguard/url_validation.py`: scheme allowlist, hostname grammar, IDNA conversion, registrable domain extraction |
| C | Feature Extraction | `phishguard/feature_extraction.py`: 35 lexical features from URL structure |
| D | Dataset Management | `ml/src/ingestion.py`: load CSV, validate schema, report class distribution |
| E | ML Training | `ml/src/train.py`: group-aware stratified split, class-balance retry, XGBoost + calibration, threshold optimization |
| F | Classification & Risk Scoring | `backend/app/services/classifier.py` + `risk_scoring.py`: predict + categorize + risk score + guidance |
| G | Threat Intelligence (optional) | `backend/app/services/threat_intelligence.py`: pluggable provider, disabled by default |
| H | Database & Scan History | SQLAlchemy models + Alembic migrations + retention job |
| I | Explainability | `backend/app/services/explainability.py`: evidence indicators + feature contributions |
| J | Scan History & Reporting | `backend/app/api/scans.py`, `reports.py`: CRUD, filters, pagination, CSV export |

## Data Flow

### Scan Request

1. Frontend sends `POST /api/v1/scan` with `{ "url": "..." }`
2. Backend validates URL via `validate_url()` → raises `UrlValidationError` for unsupported schemes
3. If valid, extracts 35 features via `extract_features()`
4. Classifier predicts phishing probability via `model_service.predict()`
5. Risk scoring produces category + risk score + guidance text
6. Explanation builder produces evidence indicators + top contributing features
7. Result persisted to SQLite (with userinfo redacted)
8. JSON response returned to frontend

### Failed Scan Path

If URL validation fails (e.g. `ftp://`), the backend returns HTTP 200 with `status="failed"`, `classification="unknown"`, `risk_score=null`, and `error_code` (e.g. `UNSUPPORTED_SCHEME`). The frontend renders a "Why it failed" block.

## Security Boundaries

- **No outbound network during scan** when `PAGE_ANALYSIS_ENABLED=false` (default). The scan path makes zero external requests.
- When page analysis is enabled, SSRF protection blocks private/reserved IPs, enforces port allowlist, limits redirects, and caps byte/time budgets.
- Rate limiting: 30 requests/minute per IP (configurable).
- Security headers on every response.
- Credentials never stored or logged.
- Userinfo (`username:password@`) stripped before persistence.

## Configuration

All runtime configuration is environment-driven via `backend/app/core/config.py`. See `.env.example` for the full list. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./phishguard.db` | Database connection string |
| `MODEL_PATH` | `ml/artifacts/phishguard_model.joblib` | Trained model artifact |
| `METRICS_PATH` | `ml/artifacts/model_metrics.json` | Evaluation metrics JSON |
| `PAGE_ANALYSIS_ENABLED` | `false` | Enable SSRF-protected page fetch |
| `RATE_LIMIT_ENABLED` | `true` | Enable per-IP rate limiting |
| `RATE_LIMIT_PER_MINUTE` | `30` | Requests per minute per IP |
| `SCAN_RETENTION_DAYS` | `90` | Days to keep scan records |

## Reproducibility

- Random seed: 42 (fixed)
- Dataset: Hassan-Albattra/URL_Phishing_Detection_Dataset (MIT license, 338,358 records)
- Split: group-aware by registrable domain (GroupShuffleSplit), 20% train / 25% validation / 25% test
- Model artifact versioned: `phishguard-url-rf-1.0.0`
- Feature importance recomputed from frozen artifact (no retraining needed)
