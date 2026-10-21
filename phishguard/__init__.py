"""
PhishGuard core.

This package is the single source of truth for URL validation, normalisation and
feature extraction.  It is imported by BOTH the offline training pipeline
(``ml/src``) and the online serving backend (``backend/app``).

Keeping one implementation guarantees the requirement that *"the feature
extractor used during live prediction is consistent with the feature extractor
used to train the selected model"*: the training script and the API call the
very same functions on the very same inputs.
"""

from phishguard.feature_schema import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    FEATURE_SPECS,
    FeatureSpec,
    feature_specs_as_dict,
)
from phishguard.url_validation import (
    UrlValidationError,
    ValidatedUrl,
    normalize_url,
    validate_url,
)

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FEATURE_SPECS",
    "FeatureSpec",
    "UrlValidationError",
    "ValidatedUrl",
    "feature_specs_as_dict",
    "normalize_url",
    "validate_url",
]

__version__ = "1.0.0"
