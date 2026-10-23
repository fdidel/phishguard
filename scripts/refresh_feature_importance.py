"""Recompute global feature importance from the persisted model artifact.

Why this exists
---------------
The training run that produced ``ml/artifacts/phishguard_model.joblib`` was
executed with scikit-learn 1.6.1, which renamed the fitted sub-estimators of
:class:`~sklearn.calibration.CalibratedClassifierCV` from ``estimators_`` to
``calibrated_classifiers_``.  The importance extractor therefore found no
estimators and wrote an empty ``feature_importance`` list into the metrics
file.  ``ml/src/train.py`` has been fixed, but re-running the whole pipeline
just to recover the importance values is wasteful.

This script recomputes the importance from the **frozen artifact** (the exact
model that is served) and writes it back into:

* ``ml/artifacts/model_metrics.json``  (served by ``/api/v1/model/metrics``)
* ``ml/reports/evaluation_report.json``
* ``ml/reports/feature_importance.png``

It never modifies the model itself, so the reported test metrics stay exactly
as they were measured.

Usage::

    python -m scripts.refresh_feature_importance
"""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib  # noqa: E402

from ml.src.train import (  # noqa: E402
    METRICS_PATH,
    MODEL_PATH,
    REPORT_DIR,
    REPORT_PATH,
    _feature_importance,
)


def _load_json(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _dump_json(path: str, payload: Dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"[refresh] wrote {path}")


def _write_plot(importances: List[Dict[str, object]]) -> None:
    """Render the feature-importance figure (best effort)."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover - plotting is best effort
        print(f"[refresh] WARNING could not create plot: {exc}")
        return

    top = list(importances[:20])[::-1]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(
        [row["feature"] for row in top],
        [row["importance"] for row in top],
        color="#0f766e",
    )
    ax.set_xlabel("Mean importance across calibrated sub-models")
    ax.set_title("Global Feature Importance")
    fig.tight_layout()
    path = os.path.join(REPORT_DIR, "feature_importance.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[refresh] wrote {path}")


def main() -> int:
    if not os.path.exists(MODEL_PATH):
        print(f"[refresh] ERROR model artifact not found at {MODEL_PATH}")
        return 1

    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    importances = _feature_importance(model)

    if not importances:
        print("[refresh] ERROR no feature importance could be extracted")
        return 1

    print(
        f"[refresh] extracted {len(importances)} feature importances; "
        f"top = {importances[0]['feature']} ({importances[0]['importance']})"
    )

    metrics = _load_json(METRICS_PATH)
    metrics["feature_importance"] = importances
    _dump_json(METRICS_PATH, metrics)

    if os.path.exists(REPORT_PATH):
        report = _load_json(REPORT_PATH)
        report["feature_importance"] = importances
        _dump_json(REPORT_PATH, report)

    _write_plot(importances)
    print("[refresh] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
