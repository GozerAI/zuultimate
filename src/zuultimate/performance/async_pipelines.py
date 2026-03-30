"""Async processing pipelines.

Items:
- #144: Async audit log processing pipeline
- #157: Async tenant provisioning pipeline

These pipelines use asyncio queues for non-blocking processing with
backpressure support.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.async_pipelines")


# ─────────────────────────────────────────────────────────────────────────────
# #144  Async audit log processing pipeline
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogProcessor:
    """Enhanced async audit log processor with filtering, enrichment, and fan-out.

    Sits downstream of the existing AuditPipeline and adds:
    - Event filtering (drop noisy events)
    - Enrichment (add computed fields)
    - Fan-out to multiple sinks (database, file, external)
    """

    def __init__(
        self,
        *,
        max_queue_size: int = 5000,
        batch_size: int = 100,
        flush_interval: float = 1.0,
    ):
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue_size)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._sinks: list[Callable[[list[dict[str, Any]]], Awaitable[None]]] = []
        self._filters: list[Callable[[dict[str, Any]], bool]] = []
        self._enrichers: list[Callable[[dict[str, Any]], dict[str, Any]]] = []
        self._running = False
        self._task: asyncio.Task | None = None
        self._processed = 0
        self._filtered = 0
        self._errors = 0

    def add_sink(self, sink: Callable[[list[dict[str, Any]]], Awaitable[None]]) -> None:
        self._sinks.append(sink)

    def add_filter(self, filter_fn: Callable[[dict[str, Any]], bool]) -> None:
        """Add a filter.  Return True to keep the event, False to drop."""
        self._filters.append(filter_fn)

    def add_enricher(self, enricher: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._enrichers.append(enricher)

    async def emit(self, event: dict[str, Any]) -> bool:
        """Enqueue an event.  Returns False if queue is full."""
        # Apply filters
        for f in self._filters:
            if not f(event):
                self._filtered += 1
                return True  # filtered out is not an error

        # Apply enrichers
        for e in self._enrichers:
            event = e(event)

        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._errors += 1
            return False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._process_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        # Final drain
        await self._flush()

    async def _process_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self._flush()

    async def _flush(self) -> None:
        batch: list[dict[str, Any]] = []
        while not self._queue.empty() and len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        if not batch:
            return

        self._processed += len(batch)
        for sink in self._sinks:
            try:
                await sink(batch)
            except Exception:
                self._errors += 1
                _log.exception("Audit log sink failed for %d events", len(batch))

    @property
    def stats(self) -> dict[str, int]:
        return {
            "processed": self._processed,
            "filtered": self._filtered,
            "errors": self._errors,
            "pending": self._queue.qsize(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# #157  Async tenant provisioning pipeline
# ─────────────────────────────────────────────────────────────────────────────

class ProvisioningStep:
    """A single step in the provisioning pipeline."""

    def __init__(
        self,
        name: str,
        handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
        *,
        retries: int = 2,
        timeout: float = 30.0,
    ):
        self.name = name
        self.handler = handler
        self.retries = retries
        self.timeout = timeout


class TenantProvisioningPipeline:
    """Async tenant provisioning pipeline with step-based execution.

    Each provisioning request flows through a series of steps (create tenant,
    create user, generate API key, configure entitlements, etc.).  Steps
    execute sequentially but the pipeline itself runs asynchronously so
    the HTTP request returns immediately with a provisioning ticket.
    """

    def __init__(self, *, max_queue_size: int = 100):
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue_size)
        self._steps: list[ProvisioningStep] = []
        self._results: dict[str, dict[str, Any]] = {}  # ticket_id -> result
        self._running = False
        self._task: asyncio.Task | None = None
        self._completed = 0
        self._failed = 0

    def add_step(self, step: ProvisioningStep) -> None:
        self._steps.append(step)

    async def submit(self, request: dict[str, Any]) -> str:
        """Submit a provisioning request.  Returns a ticket ID."""
        import uuid

        ticket_id = uuid.uuid4().hex[:16]
        request["_ticket_id"] = ticket_id
        request["_submitted_at"] = datetime.now(timezone.utc).isoformat()
        self._results[ticket_id] = {"status": "pending", "ticket_id": ticket_id}

        try:
            self._queue.put_nowait(request)
        except asyncio.QueueFull:
            self._results[ticket_id] = {"status": "rejected", "reason": "queue_full"}

        return ticket_id

    def get_status(self, ticket_id: str) -> dict[str, Any] | None:
        return self._results.get(ticket_id)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._process_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None

    async def _process_loop(self) -> None:
        while self._running:
            try:
                request = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            ticket_id = request["_ticket_id"]
            self._results[ticket_id]["status"] = "processing"
            context = dict(request)

            try:
                for step in self._steps:
                    self._results[ticket_id]["current_step"] = step.name
                    for attempt in range(step.retries + 1):
                        try:
                            context = await asyncio.wait_for(
                                step.handler(context), timeout=step.timeout
                            )
                            break
                        except asyncio.TimeoutError:
                            if attempt == step.retries:
                                raise
                            _log.warning(
                                "Step %s timed out (attempt %d/%d)",
                                step.name,
                                attempt + 1,
                                step.retries + 1,
                            )
                        except Exception:
                            if attempt == step.retries:
                                raise
                            _log.warning(
                                "Step %s failed (attempt %d/%d)",
                                step.name,
                                attempt + 1,
                                step.retries + 1,
                            )
                            await asyncio.sleep(0.5 * (attempt + 1))

                self._results[ticket_id] = {
                    "status": "completed",
                    "ticket_id": ticket_id,
                    "result": {
                        k: v for k, v in context.items() if not k.startswith("_")
                    },
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                self._completed += 1

            except Exception as exc:
                self._results[ticket_id] = {
                    "status": "failed",
                    "ticket_id": ticket_id,
                    "error": str(exc),
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                }
                self._failed += 1
                _log.error("Provisioning failed for ticket %s: %s", ticket_id, exc)

    @property
    def stats(self) -> dict[str, int]:
        return {
            "completed": self._completed,
            "failed": self._failed,
            "pending": self._queue.qsize(),
            "tracked": len(self._results),
        }
