"""Tests for posture change webhook handler."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from zuultimate.identity.workforce.models import DevicePosture
from zuultimate.identity.workforce.schemas import PostureWebhookRequest


@pytest.mark.asyncio
async def test_compliant_status_no_action(test_db):
    """Compliant devices should not trigger any revocation."""
    from zuultimate.identity.workforce.posture_router import posture_webhook

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = None

    body = PostureWebhookRequest(
        device_id="dev-1", compliance_status="compliant"
    )
    result = await posture_webhook(body, request)
    assert result["action"] == "none"
    assert result["revoked_count"] == 0


@pytest.mark.asyncio
async def test_non_compliant_no_device_found(test_db):
    """Non-compliant event for unknown device returns no_device_found."""
    from zuultimate.identity.workforce.posture_router import posture_webhook

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = None

    body = PostureWebhookRequest(
        device_id="unknown-dev", compliance_status="non_compliant"
    )
    result = await posture_webhook(body, request)
    assert result["action"] == "no_device_found"


@pytest.mark.asyncio
async def test_non_compliant_revokes_sessions(test_db):
    """Non-compliant event should revoke sessions for affected users."""
    from zuultimate.identity.workforce.posture_router import posture_webhook
    from zuultimate.identity.models import UserSession

    # Insert device posture record
    async with test_db.get_session("identity") as session:
        posture = DevicePosture(
            device_id="dev-1",
            user_id="user-1",
            mdm_managed=True,
            disk_encrypted=True,
        )
        session.add(posture)

    # Insert a user session
    async with test_db.get_session("identity") as session:
        us = UserSession(
            user_id="user-1",
            access_token_hash="hash1",
            refresh_token_hash="rhash1",
            is_consumed=False,
        )
        session.add(us)

    redis_mock = MagicMock()
    redis_mock.setex = AsyncMock()

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = redis_mock

    body = PostureWebhookRequest(
        device_id="dev-1", compliance_status="non_compliant"
    )
    result = await posture_webhook(body, request)
    assert result["action"] == "sessions_revoked"
    assert result["revoked_count"] >= 1


@pytest.mark.asyncio
async def test_non_compliant_no_redis(test_db):
    """Non-compliant event without Redis still returns ok."""
    from zuultimate.identity.workforce.posture_router import posture_webhook

    async with test_db.get_session("identity") as session:
        posture = DevicePosture(
            device_id="dev-2",
            user_id="user-2",
            mdm_managed=True,
        )
        session.add(posture)

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = None

    body = PostureWebhookRequest(
        device_id="dev-2", compliance_status="non_compliant"
    )
    result = await posture_webhook(body, request)
    assert result["status"] == "ok"
    assert result["revoked_count"] == 0


@pytest.mark.asyncio
async def test_posture_webhook_request_schema():
    body = PostureWebhookRequest(
        device_id="dev-1",
        compliance_status="non_compliant",
        reason="MDM unenrolled",
    )
    assert body.device_id == "dev-1"
    assert body.compliance_status == "non_compliant"
    assert body.reason == "MDM unenrolled"


@pytest.mark.asyncio
async def test_multiple_devices_same_user(test_db):
    """Multiple device postures for same user still works."""
    from zuultimate.identity.workforce.posture_router import posture_webhook

    async with test_db.get_session("identity") as session:
        for i in range(3):
            session.add(DevicePosture(
                device_id="multi-dev",
                user_id=f"user-multi-{i}",
            ))

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = None

    body = PostureWebhookRequest(
        device_id="multi-dev", compliance_status="non_compliant"
    )
    result = await posture_webhook(body, request)
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_redis_error_handled_gracefully(test_db):
    """Redis errors during setex should not crash the webhook."""
    from zuultimate.identity.workforce.posture_router import posture_webhook
    from zuultimate.identity.models import UserSession

    async with test_db.get_session("identity") as session:
        session.add(DevicePosture(device_id="dev-err", user_id="user-err"))

    async with test_db.get_session("identity") as session:
        session.add(UserSession(
            user_id="user-err",
            access_token_hash="hash-err",
            refresh_token_hash="rhash-err",
            is_consumed=False,
        ))

    redis_mock = MagicMock()
    redis_mock.setex = AsyncMock(side_effect=ConnectionError("redis down"))

    request = MagicMock()
    request.app.state.db = test_db
    request.app.state.redis = redis_mock

    body = PostureWebhookRequest(
        device_id="dev-err", compliance_status="non_compliant"
    )
    # Should not raise
    result = await posture_webhook(body, request)
    assert result["status"] == "ok"
    assert result["revoked_count"] >= 1
