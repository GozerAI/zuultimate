"""Composite and partial indexes for session lookup optimization.

Items #1 (composite indexes on session lookup columns) and
#12 (partial index on active sessions only).

These indexes are applied via SQLAlchemy __table_args__ on the UserSession model
and can also be created via Alembic migration. This module provides a helper
to verify index presence at startup.
"""

from __future__ import annotations

from sqlalchemy import Index, inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.indexes")

# ── Index definitions ────────────────────────────────────────────────────────
# These are the recommended indexes.  They are also declared on the model
# via __table_args__ so ``create_all()`` picks them up automatically.

#: Composite index for fast session lookup by user + active + expiry
IDX_SESSION_USER_ACTIVE_EXPIRES = Index(
    "ix_user_sessions_user_active_expires",
    "user_id",
    "expires_at",
    "is_consumed",
)

#: Partial index on active (unconsumed) sessions only — SQLite ignores the
#: ``where`` clause but PostgreSQL will use it to shrink the index size.
IDX_SESSION_ACTIVE_ONLY = Index(
    "ix_user_sessions_active_only",
    "user_id",
    "expires_at",
    sqlite_where=text("is_consumed = 0"),
    postgresql_where=text("is_consumed = false"),
)

#: Composite index on auth_events for time-range + type queries
IDX_AUDIT_TYPE_CREATED = Index(
    "ix_auth_events_type_created",
    "event_type",
    "created_at",
)


async def verify_indexes(engine: AsyncEngine) -> dict[str, bool]:
    """Check which performance indexes exist on the given engine.

    Returns a dict of {index_name: exists} for monitoring/startup logging.
    """
    expected = [
        "ix_user_sessions_user_active_expires",
        "ix_user_sessions_active_only",
        "ix_auth_events_type_created",
    ]
    results: dict[str, bool] = {}

    async with engine.connect() as conn:
        def _check(connection):
            insp = inspect(connection)
            existing_tables = insp.get_table_names()
            found_indexes: set[str] = set()
            for table in existing_tables:
                for idx in insp.get_indexes(table):
                    found_indexes.add(idx["name"])
            return found_indexes

        found = await conn.run_sync(_check)

    for name in expected:
        present = name in found
        results[name] = present
        if not present:
            _log.warning("Performance index %s not found", name)
        else:
            _log.debug("Performance index %s verified", name)

    return results
