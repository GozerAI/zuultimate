"""Unit tests for webhook event bus."""

import pytest

from zuultimate.common.webhooks import WebhookService, _matches_filter, _sign_payload


def test_matches_filter_wildcard():
    assert _matches_filter("security.scan", "*") is True


def test_matches_filter_exact():
    assert _matches_filter("security.scan", "security.scan") is True
    assert _matches_filter("security.scan", "security.guard") is False


def test_matches_filter_glob():
    assert _matches_filter("security.scan", "security.*") is True
    assert _matches_filter("pos.transaction", "security.*") is False


def test_matches_filter_comma_separated():
    assert _matches_filter("security.scan", "security.*, pos.*") is True
    assert _matches_filter("pos.transaction", "security.*, pos.*") is True
    assert _matches_filter("crm.sync", "security.*, pos.*") is False


def test_sign_payload():
    sig = _sign_payload('{"test": true}', "secret123")
    assert len(sig) == 64  # SHA-256 hex digest
    # Same input = same output
    assert _sign_payload('{"test": true}', "secret123") == sig
    # Different secret = different output
    assert _sign_payload('{"test": true}', "other") != sig


@pytest.fixture
async def webhook_svc(test_db):
    return WebhookService(test_db)


async def test_create_webhook(webhook_svc):
    result = await webhook_svc.create_webhook(
        url="https://example.com/hook",
        events_filter="security.*",
        description="Security alerts",
    )
    assert result["url"] == "https://example.com/hook"
    assert result["events_filter"] == "security.*"
    assert result["is_active"] is True


async def test_list_webhooks(webhook_svc):
    await webhook_svc.create_webhook(url="https://a.com/hook")
    await webhook_svc.create_webhook(url="https://b.com/hook")
    hooks = await webhook_svc.list_webhooks()
    assert len(hooks) == 2


async def test_delete_webhook(webhook_svc):
    created = await webhook_svc.create_webhook(url="https://a.com/hook")
    await webhook_svc.delete_webhook(created["id"])
    hooks = await webhook_svc.list_webhooks()
    assert len(hooks) == 0


async def test_publish_to_matching_webhooks(webhook_svc):
    await webhook_svc.create_webhook(
        url="https://a.com/hook", events_filter="security.*"
    )
    await webhook_svc.create_webhook(
        url="https://b.com/hook", events_filter="pos.*"
    )

    deliveries = await webhook_svc.publish(
        "security.scan", {"threat_score": 0.8}
    )
    assert len(deliveries) == 1
    assert deliveries[0]["url"] == "https://a.com/hook"
    assert deliveries[0]["status"] == "queued"


async def test_publish_to_wildcard_webhook(webhook_svc):
    await webhook_svc.create_webhook(url="https://all.com/hook", events_filter="*")
    deliveries = await webhook_svc.publish("anything.here", {})
    assert len(deliveries) == 1


async def test_publish_no_matching_webhooks(webhook_svc):
    await webhook_svc.create_webhook(
        url="https://a.com/hook", events_filter="security.*"
    )
    deliveries = await webhook_svc.publish("crm.sync", {})
    assert len(deliveries) == 0


async def test_publish_includes_signature_when_secret_set(webhook_svc):
    await webhook_svc.create_webhook(
        url="https://a.com/hook",
        events_filter="*",
        secret="my-webhook-secret",
    )
    deliveries = await webhook_svc.publish("test.event", {"key": "value"})
    assert len(deliveries) == 1
    assert "signature" in deliveries[0]
    assert len(deliveries[0]["signature"]) == 64
