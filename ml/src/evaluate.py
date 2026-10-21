"""Model evaluation utilities: metrics, confusion matrix, ROC, calibration."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def classification_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, float]:
    """Accuracy / precision / recall / F1 for the *phishing* (positive) class."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }


def error_rates(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, float]:
    """False-positive rate, false-negative rate, specificity and sensitivity."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    specificity = tn / (fp + tn) if (fp + tn) else 0.0
    sensitivity = tp / (tp + fn) if (tp + fn) else 0.0

    return {
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "specificity": float(specificity),
        "sensitivity": float(sensitivity),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def confusion_matrix_dict(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, object]:
    """Confusion matrix as a nested, JSON-serialisable dictionary."""
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "labels": ["legitimate", "phishing"],
        "matrix": matrix.tolist(),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "total": int(matrix.sum()),
    }


def roc_metrics(y_true: Sequence[int], y_prob: Sequence[float]) -> Dict[str, object]:
    """ROC-AUC, average precision and the ROC curve points."""
    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob, dtype=float)

    result: Dict[str, object] = {}
    if len(np.unique(y_true)) < 2:
        result["roc_auc"] = None
        result["average_precision"] = None
        result["curve"] = []
        return result

    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    result["roc_auc"] = float(roc_auc_score(y_true, y_prob))
    result["average_precision"] = float(average_precision_score(y_true, y_prob))
    # Subsample the curve so the JSON payload stays small.
    step = max(1, len(fpr) // 200)
    result["curve"] = [
        {"fpr": float(fpr[i]), "tpr": float(tpr[i]), "threshold": float(thresholds[i])}
        for i in range(0, len(fpr), step)
    ]
    return result


def expected_calibration_error(
    y_true: Sequence[int], y_prob: Sequence[float], n_bins: int = 10
) -> float:
    """Expected Calibration Error (ECE) with equal-width probability bins."""
    y_true = np.asarray(y_true, dtype=float)
    y_prob = np.asarray(y_prob, dtype=float)
    if len(y_true) == 0:
        return 0.0

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        in_bin = (y_prob > low) & (y_prob <= high) if i > 0 else (y_prob >= low) & (y_prob <= high)
        if not in_bin.any():
            continue
        accuracy = float(y_true[in_bin].mean())
        confidence = float(y_prob[in_bin].mean())
        ece += (in_bin.sum() / len(y_true)) * abs(accuracy - confidence)
    return float(ece)


def calibration_metrics(y_true: Sequence[int], y_prob: Sequence[float]) -> Dict[str, float]:
    """Brier score and ECE - evidence that the reported probability is calibrated."""
    return {
        "brier_score": float(brier_score_loss(y_true, np.asarray(y_prob, dtype=float))),
        "expected_calibration_error": expected_calibration_error(y_true, y_prob),
    }


def full_report(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    y_prob: Optional[Sequence[float]] = None,
) -> Dict[str, object]:
    """Assemble the complete evaluation payload for one model."""
    report: Dict[str, object] = {
        "metrics": classification_metrics(y_true, y_pred),
        "error_rates": error_rates(y_true, y_pred),
        "confusion_matrix": confusion_matrix_dict(y_true, y_pred),
        "classification_report": classification_report(
            y_true, y_pred, target_names=["legitimate", "phishing"], output_dict=True, zero_division=0
        ),
    }
    if y_prob is not None:
        report["roc"] = roc_metrics(y_true, y_prob)
        report["calibration"] = calibration_metrics(y_true, y_prob)
    return report


def measure_inference_latency(
    predict_fn, X: np.ndarray, n_repeats: int = 20
) -> Dict[str, float]:
    """Measure single-URL inference latency in milliseconds."""
    import time

    if len(X) == 0:
        return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "samples": 0}

    sample = X[0]
    timings: List[float] = []
    for _ in range(n_repeats):
        start = time.perf_counter()
        predict_fn(sample.reshape(1, -1))
        timings.append((time.perf_counter() - start) * 1000.0)

    timings_sorted = sorted(timings)
    p50 = timings_sorted[len(timings) // 2]
    p95 = timings_sorted[min(len(timings) - 1, int(len(timings) * 0.95))]
    return {
        "mean_ms": float(np.mean(timings)),
        "p50_ms": float(p50),
        "p95_ms": float(p95),
        "samples": int(len(timings)),
    }
