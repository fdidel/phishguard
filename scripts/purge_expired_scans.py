"""Retention job: delete scan records older than the configured retention window.

The project stores *only* analysis metadata (URL, verdict, features).  No
credentials, cookies or page content are ever persisted, so the retention
policy is about data minimisation rather than secret hygiene.

Usage (from the project root)::

    python scripts/purge_expired_scans.py            # dry run, prints a summary
    python scripts/purge_expired_scans.py --apply    # actually delete
    python scripts/purge_expired_scans.py --apply --days 30

``--apply`` is required to mutate the database; without it the script only
reports what *would* be removed, so it is safe to run from a cron job that
may be mis-configured.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import delete, func, select  # noqa: E402

from backend.app.core.config import settings  # noqa: E402
from backend.app.database.base import SessionLocal, engine, init_db  # noqa: E402
from backend.app.models.scan import Feedback, Scan  # noqa: E402

logger = logging.getLogger("phishguard.retention")


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Retention window in days (default: SCAN_RETENTION_DAYS setting).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the deletion. Without this flag the run is a dry run.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _parse_args(argv)

    days = args.days if args.days is not None else settings.scan_retention_days
    if days < 1:
        logger.error("--days must be a positive integer, got %s", days)
        return 2

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    logger.info("Retention window: %s day(s); removing scans created before %s", days, cutoff.isoformat())

    # Make sure the schema exists (no-op when Alembic manages it).
    init_db()

    with SessionLocal() as db:
        total_scans = db.execute(select(func.count()).select_from(Scan)).scalar() or 0
        expired = db.execute(
            select(func.count()).select_from(Scan).where(Scan.created_at < cutoff)
        ).scalar() or 0
        expired_feedback = db.execute(
            select(func.count())
            .select_from(Feedback)
            .where(Feedback.scan_id.in_(select(Scan.id).where(Scan.created_at < cutoff)))
        ).scalar() or 0

        print("=" * 72)
        print("PhishGuard retention report")
        print("=" * 72)
        print(f"database           : {settings.database_url}")
        print(f"retention (days)   : {days}")
        print(f"cutoff             : {cutoff.isoformat()}")
        print(f"scans in database  : {total_scans}")
        print(f"scans to remove    : {expired}")
        print(f"feedback to remove : {expired_feedback}")

        if not args.apply:
            print("-" * 72)
            print("DRY RUN - nothing was deleted. Re-run with --apply to remove the rows.")
            return 0

        # ``ondelete="CASCADE"`` removes the feedback rows with their scan, but
        # SQLite only enforces it when the PRAGMA is enabled, so the feedback
        # rows are removed explicitly as well.
        db.execute(delete(Feedback).where(Feedback.scan_id.in_(select(Scan.id).where(Scan.created_at < cutoff))))
        db.execute(delete(Scan).where(Scan.created_at < cutoff))
        db.commit()

        remaining = db.execute(select(func.count()).select_from(Scan)).scalar() or 0
        print("-" * 72)
        print(f"APPLIED - removed {expired} scan(s) and {expired_feedback} feedback row(s).")
        print(f"scans remaining    : {remaining}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
