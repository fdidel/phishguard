"""
Training pipeline for the PhishGuard phishing detection model.

Run with::

    python -m ml.src.train                    # full run
    python -m ml.src.train --fast             # quick smoke run (20k rows)
    python -m ml.src.train --rebuild-dataset  # re-ingest the raw CSVs first

Pipeline stages
---------------
1. ingest + clean the dataset,
2. group-aware, class-balanced train/validation/test split,
3. fit the preprocessing pipeline **on the training partition only**,
4. compare Logistic Regression, Decision Tree, Random Forest, SVM and XGBoost
   with cross-validation on the training partition,
5. calibrate the winner's probabilities (sigmoid calibration, internal CV),
6. select the operating thresholds on the validation partition,
7. refit the calibrated winner on the **full** training partition,
8. re-select the thresholds on the validation partition using the final model,
9. evaluate the frozen model once on the untouched test partition,
10. persist model, metrics, evaluation report and plots.

Compute budget
--------------
Stage 4 compares five candidates, each wrapped in a 3-fold
:class:`~sklearn.calibration.CalibratedClassifierCV`.  The RBF-SVM is by far
the most expensive candidate, so the *comparison* stage is executed on a
stratified subsample of the training partition (``MAX_FIT_ROWS``).  The
**final** model is always refit on the complete training partition, so the
reported test metrics are produced by a model that saw all available training
data.  Both facts are recorded in the metrics file.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import fbeta_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from ml.src.evaluate import (
    classification_metrics,
    full_report,
    measure_inference_latency,
    roc_metrics,
)
from ml.src.preprocessing import (
    RANDOM_SEED,
    class_distribution_report,
    load_or_build_cleaned,
    split_dataframe,
)
from phishguard.feature_schema import (
    DEFAULT_MODEL_VERSION,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    feature_specs_as_dict,
)

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - xgboost is optional
    XGBClassifier = None  # type: ignore

# --------------------------------------------------------------------------
# Paths and configuration
# --------------------------------------------------------------------------

ARTIFACT_DIR = os.environ.get("PHISHGUARD_ARTIFACT_DIR", os.path.join("ml", "artifacts"))
REPORT_DIR = os.environ.get("PHISHGUARD_REPORT_DIR", os.path.join("ml", "reports"))
MODEL_PATH = os.path.join(ARTIFACT_DIR, "phishguard_model.joblib")
METRICS_PATH = os.path.join(ARTIFACT_DIR, "model_metrics.json")
REPORT_PATH = os.path.join(REPORT_DIR, "evaluation_report.json")
COMPARISON_CSV = os.path.join(REPORT_DIR, "model_comparison.csv")

#: Target recall/precision trade-off used when picking the operating point.
#: beta > 1 weights recall more than precision, which is the right trade-off
#: for phishing detection where a missed phishing site is more harmful than a
#: false alarm (subject to the hard FPR ceiling below).
F_BETA = 1.5

#: Hard ceiling on the false-positive rate accepted on the validation set.
MAX_FPR = 0.05

#: Stricter ceiling used for the DANGEROUS band.
DANGEROUS_MAX_FPR = 0.02

#: Number of outer cross-validation folds used for model comparison.
CV_FOLDS = 3

#: Number of internal folds used for probability calibration.
CALIBRATION_FOLDS = 3

#: Maximum number of training rows used during the model *comparison* stage.
MAX_FIT_ROWS = int(os.environ.get("PHISHGUARD_MAX_FIT_ROWS", "50000"))


# --------------------------------------------------------------------------
# Candidate models
# --------------------------------------------------------------------------


def _imputer():
    """SimpleImputer that fills any (unexpected) missing numeric value."""
    from sklearn.impute import SimpleImputer

    return SimpleImputer(strategy="median")


def build_candidates() -> Dict[str, Pipeline]:
    """Return the candidate classifiers, each wrapped in a fresh pipeline.

    The preprocessing step (imputation + scaling) lives *inside* the pipeline
    so that it is fitted on training data only during cross validation, which
    prevents leakage.
    """
    candidates: Dict[str, Pipeline] = {}

    candidates["Logistic Regression"] = Pipeline(
        [
            ("imputer", _imputer()),
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000, C=1.0, class_weight="balanced", random_state=RANDOM_SEED
                ),
            ),
        ]
    )

    candidates["Decision Tree"] = Pipeline(
        [
            ("imputer", _imputer()),
            (
                "clf",
                DecisionTreeClassifier(
                    max_depth=20,
                    min_samples_leaf=5,
                    class_weight="balanced",
                    random_state=RANDOM_SEED,
                ),
            ),
        ]
    )

    candidates["Random Forest"] = Pipeline(
        [
            ("imputer", _imputer()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=300,
                    max_depth=None,
                    min_samples_leaf=1,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=RANDOM_SEED,
                ),
            ),
        ]
    )

    # probability=False: the outer CalibratedClassifierCV supplies
    # calibrated probabilities, and libsvm's own internal probability
    # calibration would multiply the training cost by five.
    candidates["SVM"] = Pipeline(
        [
            ("imputer", _imputer()),
            ("scaler", StandardScaler()),
            (
                "clf",
                SVC(
                    kernel="rbf",
                    C=10.0,
                    gamma="scale",
                    class_weight="balanced",
                    probability=False,
                    random_state=RANDOM_SEED,
                ),
            ),
        ]
    )

    if XGBClassifier is not None:
        candidates["XGBoost"] = Pipeline(
            [
                ("imputer", _imputer()),
                (
                    "clf",
                    XGBClassifier(
                        n_estimators=300,
                        max_depth=8,
                        learning_rate=0.1,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        min_child_weight=1,
                        reg_lambda=1.0,
                        eval_metric="logloss",
                        tree_method="hist",
                        n_jobs=-1,
                        random_state=RANDOM_SEED,
                    ),
                ),
            ]
        )
    else:  # pragma: no cover
        print("[train] WARNING: xgboost is unavailable - skipping that candidate")

    return candidates


def calibrate(pipeline: Pipeline, X: np.ndarray, y: np.ndarray) -> CalibratedClassifierCV:
    """Wrap ``pipeline`` in a sigmoid-calibrated ensemble and fit it."""
    calibrated = CalibratedClassifierCV(
        estimator=pipeline, method="sigmoid", cv=CALIBRATION_FOLDS
    )
    calibrated.fit(X, y)
    return calibrated


# --------------------------------------------------------------------------
# Threshold selection
# --------------------------------------------------------------------------


def _confusion(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[int, int, int, int]:
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    return tn, fp, fn, tp


def select_thresholds(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    fbeta: float = F_BETA,
    max_fpr: float = MAX_FPR,
    dangerous_max_fpr: float = DANGEROUS_MAX_FPR,
) -> Dict[str, float]:
    """Select the SAFE/SUSPICIOUS/DANGEROUS thresholds on the validation set.

    * The **suspicious** threshold maximises the F-beta score subject to a hard
      false-positive-rate ceiling.
    * The **dangerous** threshold maximises recall on the phishing class
      subject to a stricter false-positive-rate ceiling, so that the DANGEROUS
      band is high-precision.

    Both thresholds are chosen on the validation partition only; the test
    partition is never used for threshold selection.
    """
    thresholds = np.unique(np.concatenate([np.linspace(0.0, 1.0, 201), [0.5]]))

    best_threshold = 0.5
    best_score = -1.0
    best_fpr = 1.0

    for threshold in thresholds:
        predictions = (y_prob >= threshold).astype(int)
        tn, fp, fn, tp = _confusion(y_true, predictions)
        fpr = fp / max(fp + tn, 1)
        if fpr > max_fpr:
            continue
        score = fbeta_score(y_true, predictions, beta=fbeta, zero_division=0)
        if score > best_score:
            best_score = score
            best_threshold = float(threshold)
            best_fpr = float(fpr)

    dangerous_threshold = 0.5
    best_recall = -1.0
    dangerous_fpr = 1.0
    for threshold in thresholds:
        predictions = (y_prob >= threshold).astype(int)
        tn, fp, fn, tp = _confusion(y_true, predictions)
        fpr = fp / max(fp + tn, 1)
        if fpr > dangerous_max_fpr:
            continue
        recall = tp / max(tp + fn, 1)
        if recall > best_recall:
            best_recall = recall
            dangerous_threshold = float(threshold)
            dangerous_fpr = float(fpr)

    return {
        "suspicious_threshold": round(best_threshold, 4),
        "dangerous_threshold": round(dangerous_threshold, 4),
        "safe_threshold": round(best_threshold, 4),
        "validation_fbeta": float(best_score),
        "validation_fpr_at_threshold": float(best_fpr),
        "validation_recall_at_dangerous_threshold": float(max(best_recall, 0.0)),
        "validation_fpr_at_dangerous_threshold": float(dangerous_fpr),
        "f_beta": fbeta,
        "max_fpr_constraint": max_fpr,
        "dangerous_max_fpr_constraint": dangerous_max_fpr,
    }


def classify_with_thresholds(
    y_prob: np.ndarray, suspicious_threshold: float, dangerous_threshold: float
) -> np.ndarray:
    """Map probabilities onto the three operational risk bands."""
    result = np.full(y_prob.shape, "safe", dtype=object)
    result[y_prob >= suspicious_threshold] = "suspicious"
    result[y_prob >= dangerous_threshold] = "dangerous"
    return result


# --------------------------------------------------------------------------
# Main training routine
# --------------------------------------------------------------------------


def _stratified_subsample(
    X: np.ndarray, y: np.ndarray, max_rows: int, seed: int
) -> Tuple[np.ndarray, np.ndarray]:
    """Stratified subsample of the training partition for the comparison stage."""
    if max_rows <= 0 or len(y) <= max_rows:
        return X, y
    rng = np.random.RandomState(seed)
    indices: List[int] = []
    for label in np.unique(y):
        label_indices = np.where(y == label)[0]
        take = int(round(len(label_indices) * max_rows / len(y)))
        take = max(1, min(take, len(label_indices)))
        chosen = rng.choice(label_indices, size=take, replace=False)
        indices.extend(chosen.tolist())
    indices = np.array(sorted(indices))
    return X[indices], y[indices]


def train(
    fast: bool = False,
    max_rows: Optional[int] = None,
    force_rebuild: bool = False,
) -> Dict[str, object]:
    """Run the full pipeline and persist every artifact."""
    started = time.time()
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

    print("[train] === 1/8 loading dataset ===")
    df = load_or_build_cleaned(force=force_rebuild)
    if fast and max_rows is None:
        max_rows = 20000
    if max_rows:
        df = df.sample(n=min(max_rows, len(df)), random_state=RANDOM_SEED).reset_index(drop=True)
        print(f"[train] subsampled to {len(df):,} rows for this run")

    print("[train] === 2/8 splitting (group-aware by registrable domain) ===")
    split = split_dataframe(df)
    distribution = class_distribution_report(df["is_phishing"].to_numpy())

    print("[train] === 3/8 comparing candidate models (cross-validated) ===")
    X_fit, y_fit = _stratified_subsample(
        split.X_train, split.y_train, MAX_FIT_ROWS, RANDOM_SEED
    )
    print(
        f"[train] comparison stage uses {len(y_fit):,} of "
        f"{len(split.y_train):,} training rows (cap={MAX_FIT_ROWS:,})"
    )

    candidates = build_candidates()
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)

    comparison_rows: List[Dict[str, object]] = []
    fitted: Dict[str, CalibratedClassifierCV] = {}

    for name, pipeline in candidates.items():
        t0 = time.time()
        calibrated = calibrate(pipeline, X_fit, y_fit)
        scores = cross_val_score(
            calibrated, X_fit, y_fit, cv=cv, scoring="f1", n_jobs=1
        )
        fitted[name] = calibrated
        fit_time = time.time() - t0

        valid_prob = calibrated.predict_proba(split.X_valid)[:, 1]
        valid_pred = (valid_prob >= 0.5).astype(int)
        metrics = classification_metrics(split.y_valid, valid_pred)
        roc = roc_metrics(split.y_valid, valid_prob)

        row = {
            "model": name,
            "cv_f1_mean": float(scores.mean()),
            "cv_f1_std": float(scores.std()),
            "validation_accuracy": metrics["accuracy"],
            "validation_precision": metrics["precision"],
            "validation_recall": metrics["recall"],
            "validation_f1": metrics["f1"],
            "validation_roc_auc": roc["roc_auc"],
            "fit_seconds": round(fit_time, 2),
        }
        comparison_rows.append(row)
        print(
            f"[train]   {name:<22} cv_f1={row['cv_f1_mean']:.4f}+-{row['cv_f1_std']:.4f} "
            f"val_acc={row['validation_accuracy']:.4f} val_f1={row['validation_f1']:.4f} "
            f"val_auc={row['validation_roc_auc']:.4f} ({row['fit_seconds']}s)"
        )

    comparison = pd.DataFrame(comparison_rows).sort_values(
        by=["cv_f1_mean", "validation_f1"], ascending=False
    )
    comparison.to_csv(COMPARISON_CSV, index=False)
    print(f"[train] model comparison written to {COMPARISON_CSV}")

    best_name = str(comparison.iloc[0]["model"])
    print(f"[train] === 4/8 selected candidate: {best_name} ===")

    print(f"[train] === 5/8 refitting {best_name} on the FULL training partition ===")
    final_model = calibrate(candidates[best_name], split.X_train, split.y_train)

    print("[train] === 6/8 selecting thresholds on the validation partition ===")
    valid_prob = final_model.predict_proba(split.X_valid)[:, 1]
    thresholds = select_thresholds(split.y_valid, valid_prob)
    print(
        f"[train] thresholds: suspicious>={thresholds['suspicious_threshold']} "
        f"dangerous>={thresholds['dangerous_threshold']} "
        f"(validation FPR {thresholds['validation_fpr_at_threshold']:.4f})"
    )

    print("[train] === 7/8 final evaluation on the untouched test partition ===")
    test_prob = final_model.predict_proba(split.X_test)[:, 1]
    test_pred = (test_prob >= thresholds["suspicious_threshold"]).astype(int)
    test_report = full_report(split.y_test, test_pred, test_prob)

    latency = measure_inference_latency(
        lambda row: final_model.predict_proba(row), split.X_test[:1], n_repeats=30
    )
    test_report["inference_latency"] = latency

    print(
        f"[train] TEST acc={test_report['metrics']['accuracy']:.4f} "
        f"prec={test_report['metrics']['precision']:.4f} "
        f"rec={test_report['metrics']['recall']:.4f} "
        f"f1={test_report['metrics']['f1']:.4f} "
        f"auc={test_report['roc']['roc_auc']:.4f}"
    )

    print("[train] === 8/8 extracting importance and persisting artifacts ===")
    importances = _feature_importance(final_model)

    model_version = DEFAULT_MODEL_VERSION
    artifact = {
        "model": final_model,
        "model_version": model_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "feature_specs": feature_specs_as_dict(),
        "thresholds": thresholds,
        "selected_model_name": best_name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
    }
    joblib.dump(artifact, MODEL_PATH, compress=3)
    print(
        f"[train] model artifact written to {MODEL_PATH} "
        f"({os.path.getsize(MODEL_PATH)/1024:.1f} KiB)"
    )

    metrics_payload = {
        "model_version": model_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "selected_model": best_name,
        "trained_at": artifact["trained_at"],
        "random_seed": RANDOM_SEED,
        "dataset": {
            "name": "Phishing URL Dataset (Hassan-Albattra/URL_Phishing_Detection_Dataset)",
            "source_url": (
                "https://github.com/Hassan-Albattra/URL_Phishing_Detection_Dataset"
            ),
            "license": "MIT",
            "records_used": int(len(df)),
            "class_distribution": distribution,
        },
        "split": {
            "strategy": "group-aware by registrable domain, class-balance verified",
            "sizes": split.sizes(),
            "distribution": split.distribution(),
            "test_size": 0.20,
            "validation_size": 0.25,
            "comparison_stage_max_fit_rows": MAX_FIT_ROWS,
            "comparison_stage_rows_used": int(len(y_fit)),
            "final_model_fit_rows": int(len(split.y_train)),
        },
        "thresholds": thresholds,
        "test_set": test_report,
        "model_comparison": comparison_rows,
        "feature_importance": importances,
        "inference_latency": latency,
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "platform": platform.platform(),
        },
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle, indent=2)
    print(f"[train] metrics written to {METRICS_PATH}")

    report_payload = {
        "objective_1_model_comparison": comparison_rows,
        "objective_3_evaluation": test_report,
        "dataset": metrics_payload["dataset"],
        "split": metrics_payload["split"],
        "thresholds": thresholds,
        "feature_importance": importances,
        "limitations": LIMITATIONS,
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report_payload, handle, indent=2)
    print(f"[train] evaluation report written to {REPORT_PATH}")

    _write_plots(final_model, split, test_prob, test_pred, importances, best_name)

    print(f"[train] done in {time.time() - started:.1f}s")
    return metrics_payload


def _calibrated_estimators(calibrated: CalibratedClassifierCV) -> List[object]:
    """Return the fitted sub-estimators of a ``CalibratedClassifierCV``.

    scikit-learn renamed the public attribute in 1.6: the fitted
    ``_CalibratedClassifier`` wrappers now live in ``calibrated_classifiers_``,
    while older releases exposed them as ``estimators_``.  Both are supported
    so that the training pipeline stays reproducible across versions.
    """
    estimators = getattr(calibrated, "calibrated_classifiers_", None)
    if not estimators:
        estimators = getattr(calibrated, "estimators_", None)
    return list(estimators or [])


def _feature_importance(calibrated: CalibratedClassifierCV) -> List[Dict[str, object]]:
    """Extract global feature importance from the fitted pipeline(s)."""
    importances: Dict[str, float] = {}
    estimators = _calibrated_estimators(calibrated)
    if not estimators:  # pragma: no cover - defensive
        print(
            "[train] WARNING no fitted sub-estimators found on "
            f"{type(calibrated).__name__}; feature importance is empty"
        )
        return []
    for calibrated_clf in estimators:
        pipeline = getattr(calibrated_clf, "estimator", calibrated_clf)
        inner = _inner_classifier(pipeline)
        if inner is None:
            continue
        values = getattr(inner, "feature_importances_", None)
        if values is None:
            coef = getattr(inner, "coef_", None)
            if coef is not None:
                values = [abs(float(v)) for v in coef[0]]
        if values is None:
            continue
        for name, value in zip(FEATURE_NAMES, values):
            importances[name] = importances.get(name, 0.0) + float(value) / len(estimators)

    if not importances:  # pragma: no cover - defensive
        return []

    total = sum(importances.values()) or 1.0
    rows = [
        {
            "feature": name,
            "importance": round(value, 6),
            "relative_importance": round(value / total, 6),
        }
        for name, value in importances.items()
    ]
    rows.sort(key=lambda row: row["importance"], reverse=True)
    return rows


def _inner_classifier(pipeline) -> Optional[object]:
    """Return the final estimator of a sklearn Pipeline."""
    if hasattr(pipeline, "steps"):
        return pipeline.steps[-1][1]
    return pipeline


# --------------------------------------------------------------------------
# Plots
# --------------------------------------------------------------------------


def _write_plots(
    model,
    split,
    test_prob: np.ndarray,
    test_pred: np.ndarray,
    importances: List[Dict[str, object]],
    best_name: str,
) -> None:
    """Produce the evaluation figures used in the academic report."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover - plotting is best effort
        print(f"[train] WARNING: could not create plots: {exc}")
        return

    from sklearn.metrics import confusion_matrix, roc_curve

    y_true = split.y_test

    matrix = confusion_matrix(y_true, test_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(5.5, 4.8))
    im = ax.imshow(matrix, cmap="Blues")
    fig.colorbar(im, ax=ax)
    ax.set_xticks([0, 1], labels=["Legitimate", "Phishing"])
    ax.set_yticks([0, 1], labels=["Legitimate", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix - {best_name}\n(Test set, n={len(y_true):,})")
    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                f"{matrix[i, j]:,}",
                ha="center",
                va="center",
                color="white" if matrix[i, j] > matrix.max() / 2 else "black",
            )
    fig.tight_layout()
    fig.savefig(os.path.join(REPORT_DIR, "confusion_matrix.png"), dpi=150)
    plt.close(fig)

    fpr, tpr, _ = roc_curve(y_true, test_prob)
    roc = roc_metrics(y_true, test_prob)
    fig, ax = plt.subplots(figsize=(5.8, 4.8))
    ax.plot(fpr, tpr, color="#b91c1c", linewidth=2, label=f"Model (AUC = {roc['roc_auc']:.4f})")
    ax.plot([0, 1], [0, 1], "--", color="#64748b", label="Chance")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve - held-out test set")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(REPORT_DIR, "roc_curve.png"), dpi=150)
    plt.close(fig)

    if importances:
        top = importances[:20][::-1]
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.barh(
            [row["feature"] for row in top],
            [row["importance"] for row in top],
            color="#0f766e",
        )
        ax.set_xlabel("Mean impurity importance (calibrated ensemble average)")
        ax.set_title(f"Feature importance - {best_name}")
        fig.tight_layout()
        fig.savefig(os.path.join(REPORT_DIR, "feature_importance.png"), dpi=150)
        plt.close(fig)

    try:
        comparison = pd.read_csv(COMPARISON_CSV)
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.bar(comparison["model"], comparison["cv_f1_mean"], color="#1d4ed8")
        ax.set_ylabel(f"Mean {CV_FOLDS}-fold CV F1 (training partition)")
        ax.set_title("Candidate model comparison")
        plt.xticks(rotation=20, ha="right")
        fig.tight_layout()
        fig.savefig(os.path.join(REPORT_DIR, "model_comparison.png"), dpi=150)
        plt.close(fig)
    except Exception:
        pass

    print(f"[train] evaluation plots written to {REPORT_DIR}")


LIMITATIONS = [
    "The dataset is historical and static; phishing campaigns change over time, so "
    "measured performance does not guarantee performance against future campaigns.",
    "The model only observes lexical properties of the URL. A URL with an entirely "
    "ordinary structure can still host a convincing phishing page.",
    "Use of HTTPS is correlated with the benign class in the source dataset; this is a "
    "dataset artefact and the model may partially rely on it.",
    "Only 'http' and 'https' URLs are analysed; URLs submitted without a scheme are "
    "normalised by prepending 'https://', which changes the scheme-derived features "
    "relative to the submitted string.",
    "Splitting by registrable domain reduces but cannot entirely remove leakage: "
    "shared hosting providers and CDN-assigned subdomains can still place related "
    "sites in different partitions.",
    "The reported confidence values are calibrated on the validation partition only; "
    "they are estimates, not guarantees.",
    "Model comparison was performed on a stratified subsample of the training "
    "partition to keep the RBF-SVM tractable; the final deployed model is refit on "
    "the complete training partition.",
]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train the PhishGuard phishing detection model"
    )
    parser.add_argument("--fast", action="store_true", help="subsample the dataset for a quick run")
    parser.add_argument("--max-rows", type=int, default=None, help="cap the number of rows used")
    parser.add_argument("--rebuild-dataset", action="store_true", help="re-ingest the raw CSVs")
    args = parser.parse_args(argv)

    train(fast=args.fast, max_rows=args.max_rows, force_rebuild=args.rebuild_dataset)
    return 0


if __name__ == "__main__":
    sys.exit(main())
