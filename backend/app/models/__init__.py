"""ORM models package.

Importing this package registers every model on the declarative metadata so
that :func:`backend.app.database.base.init_db` can create the schema.
"""

from backend.app.models.scan import (
    Classification,
    DatasetSource,
    Feedback,
    ModelEvaluation,
    Scan,
    ScanStatus,
)

__all__ = [
    "Classification",
    "DatasetSource",
    "Feedback",
    "ModelEvaluation",
    "Scan",
    "ScanStatus",
]
