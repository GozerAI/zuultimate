"""Tests for async audit log processing and tenant provisioning pipelines."""

import asyncio

import pytest

from zuultimate.performance.async_pipelines import (
    AuditLogProcessor,
    ProvisioningStep,
    TenantProvisioningPipeline,
)


class TestAuditLogProcessor:
    """Item #144: Async audit log processing pipeline."""

    async def test_emit_and_flush(self):
        received = []

        async def sink(batch):
            received.extend(batch)

        processor = AuditLogProcessor(flush_interval=0.05, batch_size=10)
        processor.add_sink(sink)
        await processor.start()

        await processor.emit({"event_type": "login", "user": "u1"})
        await asyncio.sleep(0.15)
        await processor.stop()

        assert len(received) == 1
        assert received[0]["event_type"] == "login"

    async def test_filter_drops_events(self):
        received = []

        async def sink(batch):
            received.extend(batch)

        processor = AuditLogProcessor(flush_interval=0.05)
        processor.add_sink(sink)
        processor.add_filter(lambda e: e.get("event_type") != "noise")
        await processor.start()

        await processor.emit({"event_type": "login"})
        await processor.emit({"event_type": "noise"})
        await asyncio.sleep(0.15)
        await processor.stop()

        assert len(received) == 1
        assert processor.stats["filtered"] == 1

    async def test_enricher_adds_fields(self):
        received = []

        async def sink(batch):
            received.extend(batch)

        def enrich(event):
            event["enriched"] = True
            return event

        processor = AuditLogProcessor(flush_interval=0.05)
        processor.add_sink(sink)
        processor.add_enricher(enrich)
        await processor.start()

        await processor.emit({"event_type": "login"})
        await asyncio.sleep(0.15)
        await processor.stop()

        assert received[0]["enriched"] is True

    async def test_multiple_sinks(self):
        sink1_events = []
        sink2_events = []

        async def sink1(batch):
            sink1_events.extend(batch)

        async def sink2(batch):
            sink2_events.extend(batch)

        processor = AuditLogProcessor(flush_interval=0.05)
        processor.add_sink(sink1)
        processor.add_sink(sink2)
        await processor.start()

        await processor.emit({"event_type": "test"})
        await asyncio.sleep(0.15)
        await processor.stop()

        assert len(sink1_events) == 1
        assert len(sink2_events) == 1

    async def test_stats(self):
        processor = AuditLogProcessor()
        stats = processor.stats
        assert stats["processed"] == 0
        assert stats["filtered"] == 0
        assert stats["errors"] == 0
        assert stats["pending"] == 0

    async def test_emit_returns_true(self):
        processor = AuditLogProcessor()
        result = await processor.emit({"event_type": "test"})
        assert result is True

    async def test_queue_full_returns_false(self):
        processor = AuditLogProcessor(max_queue_size=1)
        await processor.emit({"event_type": "first"})
        result = await processor.emit({"event_type": "second"})
        assert result is False
        assert processor.stats["errors"] == 1


class TestTenantProvisioningPipeline:
    """Item #157: Async tenant provisioning pipeline."""

    async def test_submit_and_process(self):
        pipeline = TenantProvisioningPipeline()

        async def create_tenant(ctx):
            ctx["tenant_id"] = "t1"
            return ctx

        async def create_user(ctx):
            ctx["user_id"] = "u1"
            return ctx

        pipeline.add_step(ProvisioningStep("create_tenant", create_tenant))
        pipeline.add_step(ProvisioningStep("create_user", create_user))
        await pipeline.start()

        ticket_id = await pipeline.submit({"name": "Acme", "slug": "acme"})
        assert ticket_id is not None

        await asyncio.sleep(0.2)
        await pipeline.stop()

        status = pipeline.get_status(ticket_id)
        assert status is not None
        assert status["status"] == "completed"
        assert status["result"]["tenant_id"] == "t1"
        assert status["result"]["user_id"] == "u1"

    async def test_step_failure(self):
        pipeline = TenantProvisioningPipeline()

        async def failing_step(ctx):
            raise ValueError("Something broke")

        pipeline.add_step(ProvisioningStep("fail", failing_step, retries=0))
        await pipeline.start()

        ticket_id = await pipeline.submit({"name": "Fail"})
        await asyncio.sleep(0.3)
        await pipeline.stop()

        status = pipeline.get_status(ticket_id)
        assert status["status"] == "failed"
        assert "Something broke" in status["error"]

    async def test_step_retry(self):
        attempts = []

        async def flaky_step(ctx):
            attempts.append(1)
            if len(attempts) < 2:
                raise RuntimeError("Flaky")
            ctx["done"] = True
            return ctx

        pipeline = TenantProvisioningPipeline()
        pipeline.add_step(ProvisioningStep("flaky", flaky_step, retries=2))
        await pipeline.start()

        ticket_id = await pipeline.submit({"name": "Retry"})
        await asyncio.sleep(1.0)
        await pipeline.stop()

        status = pipeline.get_status(ticket_id)
        assert status["status"] == "completed"
        assert len(attempts) == 2

    async def test_get_status_unknown_ticket(self):
        pipeline = TenantProvisioningPipeline()
        assert pipeline.get_status("nonexistent") is None

    async def test_stats(self):
        pipeline = TenantProvisioningPipeline()
        stats = pipeline.stats
        assert stats["completed"] == 0
        assert stats["failed"] == 0
        assert stats["pending"] == 0

    async def test_pending_status(self):
        pipeline = TenantProvisioningPipeline()

        async def slow_step(ctx):
            await asyncio.sleep(5)
            return ctx

        pipeline.add_step(ProvisioningStep("slow", slow_step))
        # Don't start pipeline - just submit
        ticket_id = await pipeline.submit({"name": "Pending"})
        status = pipeline.get_status(ticket_id)
        assert status["status"] == "pending"
