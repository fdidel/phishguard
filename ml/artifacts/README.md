# Model Artifacts

## Files

| File | Description |
|------|-------------|
| `phishguard_model.joblib` | Serialized XGBoost model wrapped in CalibratedClassifierCV |
| `model_metrics.json` | Frozen evaluation metrics from held-out test set |

## Versioning

- Model version: `phishguard-url-rf-1.0.0`
- Feature schema version: `1.0.0`
- Trained: 2026-10-21
- Random seed: 42

## Regeneration

To retrain and regenerate artifacts:

```bash
cd ml
python src/train.py
python scripts/refresh_feature_importance.py
```

The `refresh_feature_importance.py` script recomputes feature importance from the frozen artifact without retraining.
