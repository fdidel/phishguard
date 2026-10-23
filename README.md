# PhishGuard

AI-powered phishing URL detection and website safety verification system.

BSc Computer Science Project — Nasarawa State University, Keffi
Design Science Research / Pragmatism / Waterfall Model / Supervised ML

## Quick Start

```bash
# Backend
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000

# Frontend (separate terminal)
npm install
npm run dev
```

Open http://localhost:5173

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full system design.

## API

See [docs/api.md](docs/api.md) for endpoint reference.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, component map, data flow |
| [API Reference](docs/api.md) | All endpoints, request/response schemas |
| [Dataset](docs/dataset.md) | Data source, preprocessing, feature extraction |
| [Model Card](docs/model_card.md) | Model identity, performance, limitations |
| [Security](docs/security.md) | SSRF protection, input validation, rate limiting |
| [Testing](docs/testing.md) | Test suites, coverage, acceptance criteria |
| [Deployment](docs/deployment.md) | Docker, compose, production checklist |

## Testing

```bash
# Backend (310 tests)
python -m pytest backend/tests/unit backend/tests/integration backend/tests/security -q

# Frontend (43 tests)
npm test -- --run
```

## Model Performance

| Metric | Value |
|--------|-------|
| Accuracy | 93.74% |
| Precision | 94.73% |
| Recall | 92.67% |
| F1 | 93.69% |
| FPR (safe) | 5.18% |
| FNR (dangerous) | 7.33% |

See [docs/model_card.md](docs/model_card.md) for details.

## Reproducibility

- Random seed: 42
- Dataset: Hassan-Albattra/URL_Phishing_Detection_Dataset (MIT)
- Model artifact: `ml/artifacts/phishguard_model.joblib`
- Metrics: `ml/artifacts/model_metrics.json`

## License

MIT
