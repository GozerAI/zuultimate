"""Background tasks for periodic maintenance."""

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete, select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.tasks")


class SessionCleanupTask:
    """Periodically remove expired user sessions from the database."""

    def __init__(self, db: DatabaseManager, interval_seconds: int = 300, max_age_hours: int = 24):
        self.db = db
        self.interval = interval_seconds
        self.max_age_hours = max_age_hours
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        _log.info("Session cleanup task started (interval=%ds)", self.interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        _log.info("Session cleanup task stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                removed = await self.cleanup()
                if removed > 0:
                    _log.info("Cleaned up %d expired sessions", removed)
            except Exception as exc:
                _log.error("Session cleanup error: %s", exc)
            await asyncio.sleep(self.interval)

    async def cleanup(self) -> int:
        """Remove sessions older than max_age_hours. Returns count removed."""
        from zuultimate.identity.models import UserSession

        # Use naive UTC for SQLite compatibility (SQLite drops timezone info)
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=self.max_age_hours)

        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(UserSession).where(UserSession.created_at < cutoff)
            )
            expired = result.scalars().all()
            count = len(expired)

            if count > 0:
                await session.execute(
                    sa_delete(UserSession).where(UserSession.created_at < cutoff)
                )

        return count
