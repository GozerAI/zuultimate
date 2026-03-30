"""Database query logging with slow query alerts.

Item #35: Database query logging with slow query alerts.

This module provides a self-contained query logger that can be attached to
any SQLAlchemy async engine.  It maintains a ring buffer of recent slow queries
and exposes statistics for monitoring.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.query_logging")


@dataclass
class SlowQueryRecord:
    statement: str
    elapsed_ms: float
    timestamp: float = field(default_factory=time.time)
    db_key: str = ""


class QueryLogger:
    """Structured query logger with configurable slow-query threshold.

    Unlike ``QueryTimeoutEnforcer`` (which focuses on timeouts), this logger
    keeps structured records and can emit alert callbacks for integration
    with external monitoring systems.
    """

    def __init__(
        self,
        *,
        slow_threshold_ms: float = 100.0,
        ring_size: int = 200,
        alert_callback: Any | None = None,
    ):
        self.slow_threshold_ms = slow_threshold_ms
        self._ring: deque[SlowQueryRecord] = deque(maxlen=ring_size)
        self._alert_callback = alert_callback
        self._total = 0
        self._slow = 0

    def attach(self, engine: AsyncEngine, db_key: str = "") -> None:
        sync_engine = engine.sync_engine

        @event.listens_for(sync_engine, "before_cursor_execute")
        def _before(conn, cursor, stmt, params, context, executemany):
            conn.info["_ql_start"] = time.perf_counter()

        @event.listens_for(sync_engine, "after_cursor_execute")
        def _after(conn, cursor, stmt, params, context, executemany):
            start = conn.info.pop("_ql_start", None)
            if start is None:
                return
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._total += 1

            if elapsed_ms >= self.slow_threshold_ms:
                self._slow += 1
                record = SlowQueryRecord(
                    statement=stmt[:500],
                    elapsed_ms=round(elapsed_ms, 2),
                    db_key=db_key,
                )
                self._ring.append(record)
                _log.warning(
                    "Slow query [%s] %.1fms: %.200s",
                    db_key,
                    elapsed_ms,
                    stmt,
                )
                if self._alert_callback:
                    try:
                        self._alert_callback(record)
                    except Exception:
                        pass

    def attach_all(self, engines: dict[str, AsyncEngine]) -> None:
        for key, engine in engines.items():
            self.attach(engine, db_key=key)

    @property
    def recent_slow_queries(self) -> list[dict]:
        return [
            {
                "statement": r.statement,
                "elapsed_ms": r.elapsed_ms,
                "timestamp": r.timestamp,
                "db_key": r.db_key,
            }
            for r in self._ring
        ]

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total_queries": self._total,
            "slow_queries": self._slow,
            "buffered": len(self._ring),
        }
