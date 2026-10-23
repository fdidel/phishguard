# Testing

## Test Suites

| Suite | Location | Tests | Purpose |
|-------|----------|------|---------|
| Unit | `backend/tests/unit/` | 130 | Service-level logic: URL validation, feature extraction, classification, risk scoring, explainability |
| Integration | `backend/tests/integration/` | 109 | API contract: scan, history, reports, system endpoints |
| Security | `backend/tests/security/` | 28 | SSRF, malformed input, rate limiting, security headers, credential safety |
| Frontend | `frontend/tests/` | 43 | React components: scan form, result panel, verdict badge, API client |
| **Total** | | **310** | |

## Backend Testing

### Unit Tests (`backend/tests/unit/`)

Covers:
- `test_url_validation.py`: scheme allowlist, hostname grammar, IDNA conversion, registrable domain extraction, edge cases
- `test_feature_extraction.py`: 35 features extracted correctly, zero-value skipping, schema version
- `test_classifier.py`: model loading, prediction, thresholds, feature importance, binary label
- `test_risk_scoring.py`: category labels, guidance text, risk score mapping, inconclusive assessment
- `test_explainability.py`: evidence indicators, feature contributions, documented spec keys

### Integration Tests (`backend/tests/integration/`)

Covers:
- `test_scan_api.py`: scan submission, persistence, validation (422 for bad input, 200+failed for semantically invalid URLs)
- `test_history_api.py`: list, detail, pagination, filters, search
- `test_reports_api.py`: summary aggregation, CSV export, credential redaction
- `test_system_api.py`: health, model info, metrics, feedback, OpenAPI docs

### Security Tests (`backend/tests/security/`)

Covers:
- SSRF: private IPs, reserved addresses, port allowlist, redirect loops, byte/time budgets
- Malformed input: empty url, whitespace, overlong url, unknown fields
- Rate limiting: 429 after threshold, exempt paths
- Security headers: all required headers present
- Credential safety: userinfo stripped from persisted URLs

## Frontend Testing

Covers:
- `apiClient.test.ts`: API client methods, error handling
- `verdictBadge.test.tsx`: all five verdict types, accessibility
- `scanResultPanel.test.tsx`: seven required sections, dangerous advice, failed scan treatment, failure reason rendering
- `scanForm.test.tsx`: valid submission, trimming, scheme rejection

## Test Isolation

- In-memory SQLite via `StaticPool` + `get_db` override
- Lifespan skipped in tests (model loaded from real artifact)
- Rate limiter disabled by default via `neutral_rate_limit` fixture
- Each test gets a fresh database session

## Running Tests

```bash
# Backend (all suites)
python -m pytest backend/tests/unit backend/tests/integration backend/tests/security -q --tb=short

# Frontend
npm test -- --run

# Type check + build
npm run typecheck && npm run build
```

## Acceptance Criteria

All 19 acceptance criteria are covered by the test suites above. Each criterion maps to one or more test cases. See `docs/final_report.md` for the full mapping.
