"""
Dataset ingestion and cleaning for the PhishGuard training pipeline.

The dataset is the raw ``label,url`` CSV files shipped with the project
(Hassan-Albattra/URL_Phishing_Detection_Dataset, MIT license).  This module:

1. Loads both CSVs.
2. Drops malformed rows.
3. Deduplicates by URL.
4. Binarises the labels into a single ``is_phishing`` target.
5. Builds the feature matrix using :mod:`phishguard.feature_extraction` so that
   training and live prediction use the *exact same* features.

No test data is touched here - all transformations happen on the full set and
the split is performed in :mod:`ml.src.preprocessing`.
"""

from __future__ import annotations

import os

import pandas as pd

from phishguard.feature_extraction import extract_features_batch
from phishguard.url_validation import UrlValidationError, validate_url

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DATASET_DIR = os.environ.get(
    "PHISHGUARD_DATASET_DIR", os.path.join("ml", "data", "raw")
)

PHISHING_CSV = os.path.join(DATASET_DIR, "phishing_urls.csv")
LEGITIMATE_CSV = os.path.join(DATASET_DIR, "legitimate_urls.csv")

#: Output of this module: a single DataFrame with columns [url, is_phishing].
OUTPUT_COLUMNS = ["url", "is_phishing"]


def load_and_clean() -> pd.DataFrame:
    """Load both CSVs, clean and merge them into one labelled frame.

    Returns
    -------
    pd.DataFrame
        Columns: ``url`` (str), ``is_phishing`` (int 0/1).
    """
    phishing_df = _load_one(PHISHING_CSV, label="phishing")
    legit_df = _load_one(LEGITIMATE_CSV, label="legitimate")

    merged = pd.concat([phishing_df, legit_df], ignore_index=True)

    # Drop rows that cannot be parsed at all.
    valid_mask = merged["url"].apply(lambda u: isinstance(u, str) and u.strip() != "")
    before = len(merged)
    merged = merged.loc[valid_mask].copy()
    dropped = before - len(merged)

    # Normalise labels to 0/1.
    label_map = {"phishing": 1, "legitimate": 0}
    merged["is_phishing"] = merged["label"].astype(str).str.strip().str.lower().map(
        label_map
    )

    # Encode labels as int.
    merged["is_phishing"] = merged["is_phishing"].astype(int)

    # Drop rows whose URL still fails validation after cleaning.
    def _ok(url: str) -> bool:
        try:
            validate_url(url)
            return True
        except UrlValidationError:
            return False

    ok_mask = merged["url"].apply(_ok)
    before2 = len(merged)
    merged = merged.loc[ok_mask].copy()
    dropped2 = before2 - len(merged)

    # Deduplicate by URL (keep first occurrence).
    before3 = len(merged)
    merged = merged.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    dropped3 = before3 - len(merged)

    print(
        f"[ingestion] loaded {len(phishing_df):,} phishing + {len(legit_df):,} "
        f"legitimate; dropped {dropped + dropped2 + dropped3} invalid/dup rows; "
        f"final={len(merged):,} rows"
    )
    print(
        f"[ingestion] class distribution: phishing={int((merged['is_phishing']==1).sum())}, "
        f"legitimate={int((merged['is_phishing']==0).sum())}"
    )
    return merged[OUTPUT_COLUMNS]


def _load_one(path: str, label: str) -> pd.DataFrame:
    """Load a single CSV file and return its rows as a DataFrame."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")
    df = pd.read_csv(path, dtype={"url": str, "label": str})
    missing = {"url", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns {sorted(missing)} in {path}")
    return df


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Build the feature matrix from a cleaned DataFrame.

    Returns a DataFrame with an extra column ``features`` containing the
    ordered feature vector as JSON-ish list.
    """
    vectors, errors = extract_features_batch(df["url"].tolist())
    if errors:
        print(f"[ingestion] skipped {len(errors)} URLs during feature extraction")
    feature_series = pd.Series(
        [list(v) for v in vectors], index=df.index
    )
    out = df.copy()
    out["features"] = feature_series
    return out


def main() -> None:
    """Entry point used by ``python -m ml.src.ingestion``."""
    df = load_and_clean()
    df = build_feature_matrix(df)
    out_path = os.environ.get(
        "PHISHGUARD_CLEANED_PATH", os.path.join("ml", "data", "processed", "cleaned_urls.csv")
    )
    os.makedirs(os.path.dirname(out_path), exist_dirs=True)
    df.to_csv(out_path, index=False)
    print(f"[ingestion] cleaned dataset written to {out_path}")


if __name__ == "__main__":
    main()
