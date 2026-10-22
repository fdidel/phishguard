"""
Model loading and inference service.

The model artifact is loaded **once** at application start-up and never
retrained at scan time.  The artifact bundles:

* the calibrated classifier,
* the model version,
* the feature schema version,
* the ordered feature names,
* the operating thresholds selected on the validation partition.

Loading is defensive: if the artifact is missing, unreadable or was trained
against a different feature schema, the service records the failure and the
API answers with ``ANALYSIS FAILED`` / ``INCONCLUSIVE`` instead of inventing a
prediction.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from backend.app.core.config import settings
from phishguard.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class ModelUnavailableError(RuntimeError):
    """Raised when the model artifact cannot be loaded or used."""


@dataclass
class Prediction:
    """A structured model prediction."""

    phishing_probability: float
    binary_label: int
    model_version: str
    feature_schema_version: str
    model_name: str
    thresholds: Dict[str, float]
    inference_ms: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "phishing_probability": self.phishing_probability,
            "binary_label": self.binary_label,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "model_name": self.model_name,
            "thresholds": self.thresholds,
            "inference_ms": self.inference_ms,
        }


class ModelService:
    """Thread-safe loader and runner for the PhishGuard model artifact."""

    def __init__(self, model_path: Optional[str] = None) -> None:
        self.model_path = model_path or settings.model_path
        self._model: Any = None
        self._artifact: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._loaded = False
        self._load_error: Optional[str] = None
        self._loaded_at: Optional[datetime] = None

    # -- lifecycle ------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        return self._loaded and self._model is not None

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def load(self, force: bool = False) -> bool:
        """Load the model artifact.  Returns ``True`` on success."""
        with self._lock:
            if self._loaded and not force:
                return True
            self._loaded = False
            self._load_error = None

            path = self.model_path
            if not os.path.exists(path):
                self._load_error = (
                    f"Model artifact not found at '{path}'. Run 'python -m ml.src.train' "
                    f"to generate it."
                )
                logger.error(self._load_error)
                return False

            try:
                artifact = joblib.load(path)
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller
                self._load_error = f"Model artifact could not be loaded: {exc}"
                logger.exception("Failed to load model artifact from %s", path)
                return False

            if not isinstance(artifact, dict) or "model" not in artifact:
                self._load_error = "Model artifact has an unexpected structure."
                logger.error(self._load_error)
                return False

            schema_version = artifact.get("feature_schema_version")
            if schema_version != FEATURE_SCHEMA_VERSION:
                self._load_error = (
                    f"Feature schema mismatch: the artifact was trained with schema "
                    f"'{schema_version}' but this code expects '{FEATURE_SCHEMA_VERSION}'. "
                    f"Retrain the model before serving requests."
                )
                logger.error(self._load_error)
                return False

            artifact_features = tuple(artifact.get("feature_names", ()))
            if artifact_features and artifact_features != FEATURE_NAMES:
                self._load_error = (
                    "Feature schema mismatch: the artifact's feature list differs from "
                    "the canonical schema. Retrain the model before serving requests."
                )
                logger.error(self._load_error)
                return False

            self._artifact = artifact
            self._model = artifact["model"]
            self._loaded = True
            self._loaded_at = datetime.now(timezone.utc)
            logger.info(
                "Loaded model '%s' (version %s) from %s",
                artifact.get("selected_model_name", "unknown"),
                artifact.get("model_version", "unknown"),
                path,
            )
            return True

    # -- inference ------------------------------------------------------

    def predict(self, features: Dict[str, float]) -> Prediction:
        """Run the model over an extracted feature vector.

        Raises
        ------
        ModelUnavailableError
            If the model is not loaded or the feature vector is incompatible.
        """
        if not self.is_loaded:
            raise ModelUnavailableError(
                self._load_error or "The detection model is not available."
            )

        missing = [name for name in FEATURE_NAMES if name not in features]
        if missing:
            raise ModelUnavailableError(
                f"Feature vector is missing {len(missing)} required feature(s): "
                f"{', '.join(missing[:5])}"
            )

        vector = np.asarray(
            [[float(features[name]) for name in FEATURE_NAMES]], dtype=np.float64
        )

        start = time.perf_counter()
        try:
            probabilities = self._model.predict_proba(vector)
        except Exception as exc:  # noqa: BLE001
            raise ModelUnavailableError(f"Model inference failed: {exc}") from exc
        inference_ms = (time.perf_counter() - start) * 1000.0

        probability = float(probabilities[0][1])
        thresholds = dict(self._artifact.get("thresholds", {}))

        return Prediction(
            phishing_probability=probability,
            binary_label=int(
                probability >= thresholds.get("suspicious_threshold", 0.5)
            ),
            model_version=str(self._artifact.get("model_version", "unknown")),
            feature_schema_version=str(
                self._artifact.get("feature_schema_version", "unknown")
            ),
            model_name=str(self._artifact.get("selected_model_name", "unknown")),
            thresholds=thresholds,
            inference_ms=inference_ms,
        )

    # -- metadata -------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        """Return metadata about the loaded model."""
        if not self.is_loaded:
            return {
                "available": False,
                "error": self._load_error,
                "model_path": self.model_path,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "supported_features": list(FEATURE_NAMES),
            }
        return {
            "available": True,
            "model_version": self._artifact.get("model_version"),
            "feature_schema_version": self._artifact.get("feature_schema_version"),
            "algorithm": self._artifact.get("selected_model_name"),
            "trained_at": self._artifact.get("trained_at"),
            "random_seed": self._artifact.get("random_seed"),
            "thresholds": self._artifact.get("thresholds", {}),
            "model_path": self.model_path,
            "loaded_at": self._loaded_at.isoformat() if self._loaded_at else None,
            "feature_count": len(FEATURE_NAMES),
            "supported_features": list(FEATURE_NAMES),
        }

    def feature_importance(self) -> List[Dict[str, Any]]:
        """Return the global feature importance recorded by the training run."""
        path = os.path.join(
            os.path.dirname(os.path.abspath(self.model_path)), "model_metrics.json"
        )
        if not os.path.exists(path):
            return []
        try:
            import json

            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload.get("feature_importance", [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not read feature importance: %s", exc)
            return []


#: Application-wide singleton.
model_service = ModelService()
