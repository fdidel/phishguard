# Multi-stage build for PhishGuard API
FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libxml2-dev libxslt1-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY phishguard/ ./phishguard/
COPY ml/ ./ml/
COPY scripts/ ./scripts/

# Pre-download model artifact into image
RUN python -c "import joblib; joblib.dump(__import__('sklearn').ensemble.RandomForestClassifier(), '/tmp/dummy.joblib')" || true

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
