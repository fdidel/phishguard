# Deployment

## Prerequisites

- Docker 24+
- Docker Compose v2+
- 4 GB RAM minimum

## Quick Start (Docker Compose)

```bash
# Clone and enter the project
cd phishing-detection-system

# Copy and edit environment
cp .env.example .env
# Edit .env: set ENVIRONMENT=production, adjust CORS_ALLOW_ORIGINS

# Build and start
docker compose up --build
```

The API will be available at `http://localhost:8000`.

## Services

| Service | Port | Purpose |
|---------|------|---------|
| api | 8000 | FastAPI backend |
| frontend | 5173 | React dev server (or nginx in prod) |

For production, replace the frontend service with an nginx container serving the built static files.

## Configuration

All configuration is via environment variables (see `.env.example`). Key settings for production:

| Variable | Production Value | Notes |
|----------|----------------|-------|
| ENVIRONMENT | production | Enables HSTS header |
| CORS_ALLOW_ORIGINS | your-domain.com | Restrict to your domains |
| PAGE_ANALYSIS_ENABLED | false | Keep SSRF surface minimal |
| RATE_LIMIT_ENABLED | true | Protect against floods |
| DATABASE_URL | postgresql://... | Use managed DB in prod |

## Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Restrict `CORS_ALLOW_ORIGINS` to your domains
- [ ] Set `PAGE_ANALYSIS_ENABLED=false` (or configure SSRF protections)
- [ ] Configure managed database (PostgreSQL)
- [ ] Set up reverse proxy (nginx/Caddy) with TLS
- [ ] Configure log rotation
- [ ] Set up monitoring/alerting
- [ ] Run `alembic upgrade head` on deploy

## Local Development

```bash
# Backend
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000

# Frontend
npm install
npm run dev
```

The frontend dev server proxies `/api` to `http://localhost:8000`.

## Model Artifact

The trained model is at `ml/artifacts/phishguard_model.joblib`. In Docker, this is baked into the image. For retraining:

```bash
cd ml
pip install -r requirements.txt
python src/train.py
python scripts/refresh_feature_importance.py
```

Then restart the API container.

## Database Migrations

```bash
# Inside the container
alembic upgrade head

# Or locally for development
cd backend
alembic upgrade head
```
