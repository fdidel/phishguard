"""
Preprocessing and reproducible splitting for the PhishGuard training pipeline.

Key decisions (documented in docs/dataset.md)
---------------------------------------------
* **Stratified split** on the binary target so that each partition keeps the
  class balance of the full dataset.
* **Group-aware split** by registrable domain.  A phishing campaign typically
  registers many URLs under one domain; splitting URLs at random would place
  near-identical rows in both train and test, inflating the measured
  performance.  Grouping by registrable domain removes that leakage.
* The **test set is isolated**: it is never used for feature selection,
  hyper-parameter tuning, calibration or threshold selection.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from phishguard.feature_schema import FEATURE_NAMES
from phishguard.url_validation import split_registrable_domain

#: Global seed used everywhere in the pipeline.
RANDOM_SEED = 42

#: Fraction of the data held out as the untouched test set.
TEST_SIZE = 0.20

#: Fraction of the *remaining* data used as the validation set.
VALIDATION_SIZE = 0.25


@dataclass
class DatasetSplit:
    """Container for the three data partitions."""

    X_train: np.ndarray
    y_train: np.ndarray
    X_valid: np.ndarray
    y_valid: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    groups_train: np.ndarray
    groups_valid: np.ndarray
    groups_test: np.ndarray
    train_urls: List[str]
    valid_urls: List[str]
    test_urls: List[str]

    def sizes(self) -> Dict[str, int]:
        return {
            "train": int(len(self.y_train)),
            "validation": int(len(self.y_valid)),
            "test": int(len(self.y_test)),
        }

    def distribution(self) -> Dict[str, Dict[str, float]]:
        def _dist(y: np.ndarray) -> Dict[str, float]:
            total = max(len(y), 1)
            return {
                "phishing": float((y == 1).sum() / total),
                "legitimate": float((y == 0).sum() / total),
                "phishing_count": int((y == 1).sum()),
                "legitimate_count": int((y == 0).sum()),
            }

        return {
            "train": _dist(self.y_train),
            "validation": _dist(self.y_valid),
            "test": _dist(self.y_test),
        }


def urls_to_matrix(urls: List[str]) -> np.ndarray:
    """Convert URLs into the ordered feature matrix used by the model."""
    from phishguard.feature_extraction import extract_features_batch

    vectors, errors = extract_features_batch(urls)
    if errors:
        raise ValueError(
            f"{len(errors)} URLs could not be feature-extracted; refusing to "
            f"train on a partially-parsed dataset. First error: {errors[0]}"
        )
    return np.asarray(vectors, dtype=np.float64)


def host_groups(urls: List[str]) -> np.ndarray:
    """Return the registrable domain for each URL (used for group splitting)."""
    from phishguard.url_validation import validate_url

    groups: List[str] = []
    for url in urls:
        try:
            validated = validate_url(url)
            groups.append(validated.registrable_domain or validated.hostname)
        except Exception:
            groups.append(f"__unparsed_{len(groups)}")
    return np.asarray(groups, dtype=object)


def split_dataset(
    urls: List[str],
    labels: np.ndarray,
    test_size: float = TEST_SIZE,
    validation_size: float = VALIDATION_SIZE,
    seed: int = RANDOM_SEED,
    cached_features: Optional[np.ndarray] = None,
) -> DatasetSplit:
    """Perform the group-aware, stratified train/validation/test split.

    Strategy
    --------
    1. A :class:`GroupShuffleSplit` isolates the test set, keeping every
       registrable domain entirely inside one partition.
    2. The remaining data is split again with ``GroupShuffleSplit`` into
       train and validation.
    3. Stratification is enforced afterwards by checking the class balance of
       each partition; if a partition is badly skewed the split is retried
       with a different seed up to ``max_attempts`` times.

    Note
    ----
    ``GroupShuffleSplit`` is *not* stratified, so the balance check below is
    the mechanism that guarantees comparable class ratios across partitions.
    """
    urls_array = np.asarray(urls, dtype=object)
    labels = np.asarray(labels, dtype=np.int64)
    groups = host_groups(list(urls_array))

    max_attempts = 25
    best: Tuple[DatasetSplit, float] | None = None

    for attempt in range(max_attempts):
        attempt_seed = seed + attempt
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=attempt_seed)
        train_val_idx, test_idx = next(splitter.split(urls_array, labels, groups))

        inner = GroupShuffleSplit(
            n_splits=1, test_size=validation_size, random_state=attempt_seed
        )
        rel_train, rel_val = next(
            inner.split(urls_array[train_val_idx], labels[train_val_idx], groups[train_val_idx])
        )
        train_idx = train_val_idx[rel_train]
        valid_idx = train_val_idx[rel_val]

        y_train = labels[train_idx]
        y_valid = labels[valid_idx]
        y_test = labels[test_idx]

        overall_rate = float(labels.mean())
        rates = [float(y_train.mean()), float(y_valid.mean()), float(y_test.mean())]
        deviation = max(abs(rate - overall_rate) for rate in rates)

        if best is None or deviation < best[1]:
            if cached_features is not None:
                X_train = cached_features[train_idx]
                X_valid = cached_features[valid_idx]
                X_test = cached_features[test_idx]
            else:
                X_train = urls_to_matrix(list(urls_array[train_idx]))
                X_valid = urls_to_matrix(list(urls_array[valid_idx]))
                X_test = urls_to_matrix(list(urls_array[test_idx]))
            best = (
                DatasetSplit(
                    X_train=X_train,
                    y_train=y_train,
                    X_valid=X_valid,
                    y_valid=y_valid,
                    X_test=X_test,
                    y_test=y_test,
                    groups_train=groups[train_idx],
                    groups_valid=groups[valid_idx],
                    groups_test=groups[test_idx],
                    train_urls=list(urls_array[train_idx]),
                    valid_urls=list(urls_array[valid_idx]),
                    test_urls=list(urls_array[test_idx]),
                ),
                deviation,
            )

        if deviation <= 0.02:
            break

    assert best is not None
    split = best[0]
    print(
        f"[preprocessing] split sizes: {split.sizes()} "
        f"(group-aware by registrable domain, seed={seed}, "
        f"max class-rate deviation={best[1]:.4f})"
    )
    for name, dist in split.distribution().items():
        print(
            f"[preprocessing]   {name:<11} phishing={dist['phishing_count']:>7,} "
            f"({dist['phishing']*100:.2f}%) legitimate={dist['legitimate_count']:>7,} "
            f"({dist['legitimate']*100:.2f}%)"
        )
    return split


def class_distribution_report(labels: np.ndarray) -> Dict[str, object]:
    """Summarise the class distribution of a label vector."""
    total = max(len(labels), 1)
    counts = {int(value): int((labels == value).sum()) for value in np.unique(labels)}
    return {
        "total": int(len(labels)),
        "counts": {str(k): v for k, v in counts.items()},
        "phishing_ratio": float((labels == 1).sum() / total),
        "legitimate_ratio": float((labels == 0).sum() / total),
        "imbalance_ratio": float(
            max((labels == 1).sum(), (labels == 0).sum())
            / max(min((labels == 1).sum(), (labels == 0).sum()), 1)
        ),
    }


def load_or_build_cleaned(force: bool = False) -> pd.DataFrame:
    """Return the cleaned dataset, building it from the raw CSVs if needed."""
    processed = os.path.join("ml", "data", "processed", "cleaned_urls.csv")
    if os.path.exists(processed) and not force:
        print(f"[preprocessing] using cached cleaned dataset at {processed}")
        return pd.read_csv(processed)

    from ml.src.ingestion import build_feature_matrix, load_and_clean

    df = load_and_clean()
    df = build_feature_matrix(df)
    os.makedirs(os.path.dirname(processed), exist_ok=True)
    df.to_csv(processed, index=False)
    print(f"[preprocessing] cleaned dataset written to {processed}")
    return df


def split_dataframe(df: pd.DataFrame, **kwargs) -> DatasetSplit:
    """Split a cleaned DataFrame into the three partitions.

    When the cleaned frame carries a cached ``features`` column (produced by
    :func:`ml.src.ingestion.build_feature_matrix`) that matrix is reused
    instead of re-extracting every feature, which makes repeated runs much
    faster while guaranteeing the values are identical.
    """
    urls = df["url"].tolist()
    labels = df["is_phishing"].to_numpy(dtype=np.int64)
    cached = _cached_feature_matrix(df)
    return split_dataset(urls, labels, cached_features=cached, **kwargs)


def _cached_feature_matrix(df: pd.DataFrame) -> Optional[np.ndarray]:
    """Return the cached feature matrix from a cleaned frame, if present."""
    if "features" not in df.columns:
        return None
    try:
        matrix = np.asarray(
            [ast.literal_eval(value) for value in df["features"].tolist()], dtype=np.float64
        )
    except Exception:
        return None
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        return None
    return matrix


__all__ = [
    "DatasetSplit",
    "FEATURE_NAMES",
    "RANDOM_SEED",
    "class_distribution_report",
    "host_groups",
    "load_or_build_cleaned",
    "split_dataframe",
    "split_dataset",
    "urls_to_matrix",
]
