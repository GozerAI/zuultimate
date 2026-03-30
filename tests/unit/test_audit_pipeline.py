"""Tests for AuditPipeline — async audit event buffering (S1.4)."""

import asyncio

import pytest

from zuultimate.infra.audit.pipeline import AuditPipeline


class TestAuditPipeline:
    @pytest.mark.asyncio
    async def test_emit_without_blocking(self):
        """emit() returns immediately without waiting for flush."""
        flushed: list[dict] = []

        async def _cb(batch):
            flushed.extend(batch)

        pipeline = AuditPipeline(_cb, flush_interval=10)  # long interval
        await pipeline.start()

        await pipeline.emit({"event_type": "login", "ip": "1.2.3.4"})
        # Event is queued but not yet flushed (interval hasn't elapsed)
        assert pipeline.pending >= 1
        assert len(flushed) == 0

        await pipeline.stop()
        # After stop, remaining events should be drained
        assert len(flushed) == 1

    @pytest.mark.asyncio
    async def test_batch_flush(self):
        """Events are flushed in batches when the interval fires."""
        flushed_batches: list[list[dict]] = []

        async def _cb(batch):
            flushed_batches.append(list(batch))

        pipeline = AuditPipeline(_cb, flush_interval=0.05, batch_size=5)
        await pipeline.start()

        for i in range(3):
            await pipeline.emit({"event_type": f"evt-{i}"})

        # Wait for at least one flush cycle
        await asyncio.sleep(0.15)

        await pipeline.stop()

        total = sum(len(b) for b in flushed_batches)
        assert total == 3

    @pytest.mark.asyncio
    async def test_shutdown_drains_remaining(self):
        """stop() flushes all remaining events before returning."""
        flushed: list[dict] = []

        async def _cb(batch):
            flushed.extend(batch)

        pipeline = AuditPipeline(_cb, flush_interval=100)  # never auto-flushes
        await pipeline.start()

        for i in range(5):
            await pipeline.emit({"i": i})

        await pipeline.stop()
        assert len(flushed) == 5

    @pytest.mark.asyncio
    async def test_queue_overflow_drops_event(self):
        """When queue is full, new events are dropped (not blocking)."""
        async def _cb(batch):
            pass

        pipeline = AuditPipeline(_cb, flush_interval=100, max_queue_size=2)
        # Don't start — so nothing is consumed
        await pipeline.emit({"a": 1})
        await pipeline.emit({"b": 2})
        await pipeline.emit({"c": 3})  # should be dropped

        assert pipeline.stats["dropped"] == 1
        assert pipeline.stats["emitted"] == 2

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        flushed: list[dict] = []

        async def _cb(batch):
            flushed.extend(batch)

        pipeline = AuditPipeline(_cb, flush_interval=0.05)
        await pipeline.start()

        await pipeline.emit({"x": 1})
        await pipeline.emit({"x": 2})

        await asyncio.sleep(0.15)
        await pipeline.stop()

        stats = pipeline.stats
        assert stats["emitted"] == 2
        assert stats["flushed"] == 2
        assert stats["dropped"] == 0

    @pytest.mark.asyncio
    async def test_flush_callback_error_requeues(self):
        """If flush_callback raises, events are re-enqueued."""
        call_count = 0

        async def _cb(batch):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("DB down")
            # Second call succeeds

        pipeline = AuditPipeline(_cb, flush_interval=0.05, batch_size=10)
        await pipeline.start()

        await pipeline.emit({"x": 1})
        # Wait for first (failed) flush + retry
        await asyncio.sleep(0.2)
        await pipeline.stop()

        # Event was re-enqueued and flushed on retry or shutdown
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        """Calling start() twice doesn't create duplicate tasks."""
        async def _cb(batch):
            pass

        pipeline = AuditPipeline(_cb, flush_interval=0.05)
        await pipeline.start()
        task1 = pipeline._task
        await pipeline.start()  # second call
        assert pipeline._task is task1  # same task
        await pipeline.stop()

    @pytest.mark.asyncio
    async def test_empty_pipeline_stop(self):
        """Stopping a pipeline with no events doesn't error."""
        async def _cb(batch):
            pass

        pipeline = AuditPipeline(_cb)
        await pipeline.start()
        await pipeline.stop()
        assert pipeline.stats["flushed"] == 0

    @pytest.mark.asyncio
    async def test_batch_size_respected(self):
        """Each flush batch is at most batch_size events."""
        batch_sizes: list[int] = []

        async def _cb(batch):
            batch_sizes.append(len(batch))

        pipeline = AuditPipeline(_cb, flush_interval=0.05, batch_size=3)
        await pipeline.start()

        for i in range(7):
            await pipeline.emit({"i": i})

        await asyncio.sleep(0.2)
        await pipeline.stop()

        for bs in batch_sizes:
            assert bs <= 3

    @pytest.mark.asyncio
    async def test_pending_property(self):
        async def _cb(batch):
            pass

        pipeline = AuditPipeline(_cb, flush_interval=100)
        assert pipeline.pending == 0

        await pipeline.emit({"a": 1})
        assert pipeline.pending == 1

        await pipeline.emit({"b": 2})
        assert pipeline.pending == 2
