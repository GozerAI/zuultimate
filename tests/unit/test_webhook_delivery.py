"""Unit tests for async webhook delivery with retries."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from zuultimate.common.webhooks import WebhookService


@pytest.fixture
def svc(test_db):
    return WebhookService(test_db)


def _mock_httpx_client(responses):
    """Create a mock httpx.AsyncClient that returns given responses in order."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=responses)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


async def test_deliver_success(svc):
    """Successful delivery on first attempt."""
    await svc.create_webhook(url="https://example.com/hook", events_filter="test.*")
    deliveries = await svc.publish("test.event", {"key": "value"})
    delivery_id = deliveries[0]["delivery_id"]

    mock_resp = MagicMock(status_code=200)
    mock_client = _mock_httpx_client([mock_resp])

    with patch("httpx.AsyncClient", return_value=mock_client):
        await svc._deliver_with_retries(
            delivery_id, "https://example.com/hook", '{"test": true}'
        )

    record = await svc.get_delivery(delivery_id)
    assert record["status"] == "delivered"
    assert record["attempt_count"] == 1


async def test_deliver_retries_on_failure(svc):
    """Retries after 5xx, then succeeds."""
    await svc.create_webhook(url="https://example.com/hook")
    deliveries = await svc.publish("test.retry", {"key": "val"})
    delivery_id = deliveries[0]["delivery_id"]

    mock_client = _mock_httpx_client([
        MagicMock(status_code=500),
        MagicMock(status_code=200),
    ])

    with patch("httpx.AsyncClient", return_value=mock_client):
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await svc._deliver_with_retries(
                delivery_id, "https://example.com/hook", '{"test": true}'
            )

    record = await svc.get_delivery(delivery_id)
    assert record["status"] == "delivered"
    assert record["attempt_count"] == 2


async def test_deliver_all_retries_exhausted(svc):
    """All retries fail — status should be 'failed'."""
    await svc.create_webhook(url="https://example.com/hook")
    deliveries = await svc.publish("test.fail", {"key": "val"})
    delivery_id = deliveries[0]["delivery_id"]

    mock_client = _mock_httpx_client([
        Exception("connection refused"),
        Exception("connection refused"),
        Exception("connection refused"),
    ])

    with patch("httpx.AsyncClient", return_value=mock_client):
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await svc._deliver_with_retries(
                delivery_id, "https://example.com/hook", '{"test": true}'
            )

    record = await svc.get_delivery(delivery_id)
    assert record["status"] == "failed"
    assert record["attempt_count"] == 3
    assert "connection refused" in record["last_error"]


async def test_deliver_with_signature(svc):
    """Delivery includes X-Webhook-Signature header."""
    await svc.create_webhook(url="https://example.com/hook", secret="mysecret")
    deliveries = await svc.publish("test.sig", {"key": "val"})
    delivery_id = deliveries[0]["delivery_id"]

    mock_resp = MagicMock(status_code=200)
    mock_client = _mock_httpx_client([mock_resp])

    with patch("httpx.AsyncClient", return_value=mock_client):
        await svc._deliver_with_retries(
            delivery_id, "https://example.com/hook", '{"test": true}',
            signature="abc123",
        )

    call_kwargs = mock_client.post.call_args
    assert call_kwargs.kwargs["headers"]["X-Webhook-Signature"] == "abc123"


async def test_get_delivery_nonexistent(svc):
    result = await svc.get_delivery("nonexistent")
    assert result is None


async def test_publish_stores_payload(svc):
    await svc.create_webhook(url="https://example.com/hook")
    deliveries = await svc.publish("test.payload", {"data": 1})
    record = await svc.get_delivery(deliveries[0]["delivery_id"])
    assert record is not None
    assert record["status"] == "queued"
