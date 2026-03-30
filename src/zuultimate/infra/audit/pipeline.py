"""Async audit event pipeline with batched database writes.

Events are collected in-memory via an asyncio queue and flushed to the
database in batches.  In production this queue would be replaced by Kafka
(or a similar durable message broker) for cross-service event streaming.
The asyncio-queue implementation establishes the correct architectural
pattern without adding a heavy runtime dependency.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Awaitable

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.infra.audit.pipeline")


class AuditPipeline:
    """Async audit event buffer with background batch flush.

    Parameters
    ----------
    flush_callback:
        Async callable that receives a list[dict] batch and persists it.
        This decouples the pipeline from any specific ORM/DB implementation.
    flush_interval:
        Seconds between automatic flush attempts.
    batch_size:
        Maximum events to flush in a single batch.
    max_queue_size:
        Upper bound on the in-memory queue.  When the queue is full,
        ``emit()`` will drop the event and log a warning rather than
        block the caller.
    """

    def __init__(
        self,
        flush_callback: Callable[[list[dict[str, Any]]], Awaitable[None]],
        *,
        flush_interval: float = 0.5,
        batch_size: int = 1000,
        max_queue_size: int = 10_000,
    ) -> None:
        self._flush_callback = flush_callback
        self._flush_interval = flush_interval
        self._batch_size = batch_size
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=max_queue_size
        )
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._events_emitted = 0
        self._events_flushed = 0
        self._events_dropped = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def emit(self, event: dict[str, Any]) -> None:
        """Non-blocking enqueue.  Drops event if queue is full."""
        try:
            self._queue.put_nowait(event)
            self._events_emitted += 1
        except asyncio.QueueFull:
            self._events_dropped += 1
            _log.warning("Audit queue full — event dropped")

    async def start(self) -> None:
        """Start background flush loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Drain remaining events and stop."""
        self._running = False
        if self._task is not None:
            # Give the loop a chance to notice _running is False
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        # Final drain
        await self._flush_remaining()

    @property
    def pending(self) -> int:
        """Number of events waiting in the queue."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict[str, int]:
        return {
            "emitted": self._events_emitted,
            "flushed": self._events_flushed,
            "dropped": self._events_dropped,
            "pending": self.pending,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _flush_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self._flush_batch()

    async def _flush_batch(self) -> None:
        batch: list[dict[str, Any]] = []
        while not self._queue.empty() and len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if batch:
            try:
                await self._flush_callback(batch)
                self._events_flushed += len(batch)
            except Exception:
                _log.exception("Failed to flush %d audit events", len(batch))
                # Re-enqueue on failure (best effort)
                for event in batch:
                    try:
                        self._queue.put_nowait(event)
                    except asyncio.QueueFull:
                        self._events_dropped += 1

    async def _flush_remaining(self) -> None:
        """Drain queue completely on shutdown."""
        while not self._queue.empty():
            await self._flush_batch()
