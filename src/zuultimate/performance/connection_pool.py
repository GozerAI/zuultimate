"""Connection pool warm-up and database query timeout enforcement.

Items:
- #2: Connection pool warm-up on startup
- #22: Database query timeout enforcement
"""

from __future__ import annotations

import asyncio
import time

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.connection_pool")


# ─────────────────────────────────────────────────────────────────────────────
# #2  Connection pool warm-up
# ─────────────────────────────────────────────────────────────────────────────

async def warm_pool(engine: AsyncEngine, *, pool_size: int = 3) -> int:
    """Pre-create connections so the first real requests don't pay cold-start.

    Opens ``pool_size`` connections in parallel, executes a trivial query on
    each (``SELECT 1``), then returns them to the pool.

    Returns the number of connections successfully warmed.
    """
    warmed = 0

    async def _warm_one() -> bool:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            _log.debug("Pool warm-up connection failed", exc_info=True)
            return False

    results = await asyncio.gather(*[_warm_one() for _ in range(pool_size)])
    warmed = sum(1 for ok in results if ok)
    _log.info("Connection pool warmed: %d/%d connections", warmed, pool_size)
    return warmed


async def warm_all_pools(
    engines: dict[str, AsyncEngine], *, pool_size: int = 2
) -> dict[str, int]:
    """Warm connection pools for all database engines.

    Returns {db_key: connections_warmed}.
    """
    results: dict[str, int] = {}
    for key, engine in engines.items():
        results[key] = await warm_pool(engine, pool_size=pool_size)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# #22  Database query timeout enforcement
# ─────────────────────────────────────────────────────────────────────────────

class QueryTimeoutEnforcer:
    """Logs slow queries and enforces per-statement timeouts.

    Attaches SQLAlchemy event listeners to an engine to measure query
    execution time.  Queries exceeding ``warn_threshold_ms`` are logged as
    warnings; those exceeding ``abort_threshold_ms`` are logged as errors.

    Note: True server-side timeout requires ``statement_timeout`` on PostgreSQL.
    For SQLite (used in tests/dev) we only do client-side timing.
    """

    def __init__(
        self,
        *,
        warn_threshold_ms: float = 200.0,
        abort_threshold_ms: float = 5000.0,
    ):
        self.warn_threshold_ms = warn_threshold_ms
        self.abort_threshold_ms = abort_threshold_ms
        self._slow_queries: list[dict] = []
        self._total_queries = 0
        self._slow_count = 0

    def attach(self, engine: AsyncEngine) -> None:
        """Register event listeners on the sync engine underlying the async wrapper."""
        sync_engine = engine.sync_engine

        @event.listens_for(sync_engine, "before_cursor_execute")
        def _before(conn, cursor, statement, parameters, context, executemany):
            conn.info["_query_start"] = time.perf_counter()

        @event.listens_for(sync_engine, "after_cursor_execute")
        def _after(conn, cursor, statement, parameters, context, executemany):
            start = conn.info.pop("_query_start", None)
            if start is None:
                return
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._total_queries += 1

            if elapsed_ms >= self.abort_threshold_ms:
                self._slow_count += 1
                entry = {
                    "statement": statement[:500],
                    "elapsed_ms": round(elapsed_ms, 2),
                    "level": "error",
                }
                self._slow_queries.append(entry)
                if len(self._slow_queries) > 100:
                    self._slow_queries = self._slow_queries[-100:]
                _log.error(
                    "Query exceeded abort threshold (%.1fms > %.1fms): %.200s",
                    elapsed_ms,
                    self.abort_threshold_ms,
                    statement,
                )
            elif elapsed_ms >= self.warn_threshold_ms:
                self._slow_count += 1
                entry = {
                    "statement": statement[:500],
                    "elapsed_ms": round(elapsed_ms, 2),
                    "level": "warn",
                }
                self._slow_queries.append(entry)
                if len(self._slow_queries) > 100:
                    self._slow_queries = self._slow_queries[-100:]
                _log.warning(
                    "Slow query (%.1fms > %.1fms): %.200s",
                    elapsed_ms,
                    self.warn_threshold_ms,
                    statement,
                )

    def attach_all(self, engines: dict[str, AsyncEngine]) -> None:
        for engine in engines.values():
            self.attach(engine)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_queries": self._total_queries,
            "slow_count": self._slow_count,
            "recent_slow": self._slow_queries[-10:],
        }


# Type hint fix for stats property
from typing import Any  # noqa: E402
