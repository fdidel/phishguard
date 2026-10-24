#!/bin/bash
# ---------------------------------------------------------------------------
# PhishGuard - Deployment Script
#
# This script prepares the project for deployment to GitHub + free hosting.
# Run it from the project root: bash scripts/deploy.sh
# ---------------------------------------------------------------------------

set -e

echo "============================================"
echo "PhishGuard Deployment Preparation"
echo "============================================"

# 1. Run all tests
echo ""
echo "[1/6] Running backend tests..."
python -m pytest backend/tests/unit backend/tests/integration backend/tests/security -q --tb=short

echo ""
echo "[2/6] Running frontend tests..."
cd frontend
npm test -- --run
cd ..

# 2. Build frontend
echo ""
echo "[3/6] Building frontend for production..."
cd frontend
npm run build
cd ..

# 3. Verify model artifact exists
echo ""
echo "[4/6] Verifying model artifacts..."
if [ ! -f "ml/artifacts/phishguard_model.joblib" ]; then
    echo "ERROR: Model artifact not found at ml/artifacts/phishguard_model.joblib"
    exit 1
fi
if [ ! -f "ml/artifacts/model_metrics.json" ]; then
    echo "ERROR: Metrics file not found at ml/artifacts/model_metrics.json"
    exit 1
fi
echo "Model artifact: OK"
echo "Metrics file: OK"

# 4. Verify feature importance is populated
echo ""
echo "[5/6] Verifying feature importance..."
python -c "
import json
with open('ml/artifacts/model_metrics.json') as f:
    metrics = json.load(f)
fi = metrics.get('feature_importance', [])
if not fi:
    print('ERROR: feature_importance is empty in model_metrics.json')
    exit(1)
print(f'Feature importance: {len(fi)} features populated')
"

# 5. Git commit
echo ""
echo "[6/6] Committing to git..."
git add -A
git commit -m "Deploy PhishGuard: $(date -u +%Y-%m-%dT%H:%M:%SZ)" || echo "No changes to commit"

echo ""
echo "============================================"
echo "Deployment preparation complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Push to GitHub:"
echo "     git remote add origin https://github.com/YOUR_USERNAME/phishguard.git"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "  2. Deploy frontend to Vercel (free):"
echo "     - Import your repo at vercel.com"
echo "     - Build command: npm run build"
echo "     - Output directory: dist"
echo ""
echo "  3. Deploy backend to Render (free):"
echo "     - Import your repo at render.com"
echo "     - Build command: pip install -r backend/requirements.txt"
echo "     - Start command: uvicorn backend.app.main:app --host 0.0.0.0 --port \$PORT"
echo ""
echo "  4. Test at:"
echo "     - Frontend: https://your-frontend.vercel.app"
echo "     - Backend:  https://your-backend.onrender.com/health"