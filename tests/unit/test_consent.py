"""Consent module — data model, service, and middleware tests.

Tests cover:
- Granting consent records
- Revoking consent with audit trail preservation
- NotFoundError on revoking nonexistent grants
- Filtering active vs historical consent records
- Re-granting after revocation creates new records
- requires_consent dependency rejection
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from zuultimate.common.exceptions import NotFoundError
from zuultimate.identity.consent.service import ConsentService
from zuultimate.identity.consent.middleware import requires_consent


@pytest.fixture
def consent_service(test_db):
    return ConsentService(test_db)


TENANT = "tenant-001"
SUBJECT = "subject-001"


@pytest.mark.asyncio
async def test_grant_consent(consent_service):
    """Grant returns a record with granted=True and a granted_at timestamp."""
    result = await consent_service.grant(
        tenant_id=TENANT,
        subject_id=SUBJECT,
        purpose="marketing",
    )
    assert result["granted"] is True
    assert result["granted_at"] is not None
    assert result["revoked_at"] is None
    assert result["purpose"] == "marketing"
    assert result["tenant_id"] == TENANT
    assert result["subject_id"] == SUBJECT
    assert result["version"] == "1.0"
    assert result["channel"] == "api"
    assert result["id"]  # non-empty UUID


@pytest.mark.asyncio
async def test_revoke_consent(consent_service):
    """Revoke sets granted=False and revoked_at on an active grant."""
    await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="analytics",
    )
    revoked = await consent_service.revoke(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="analytics",
    )
    assert revoked["granted"] is False
    assert revoked["revoked_at"] is not None


@pytest.mark.asyncio
async def test_revoke_nonexistent_raises(consent_service):
    """Revoking without an active grant raises NotFoundError."""
    with pytest.raises(NotFoundError):
        await consent_service.revoke(
            tenant_id=TENANT, subject_id=SUBJECT, purpose="marketing",
        )


@pytest.mark.asyncio
async def test_get_active_consents(consent_service):
    """Only returns non-revoked grants."""
    await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="marketing",
    )
    await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="analytics",
    )
    # Revoke one
    await consent_service.revoke(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="marketing",
    )

    active = await consent_service.get_active_consents(
        tenant_id=TENANT, subject_id=SUBJECT,
    )
    purposes = [r["purpose"] for r in active]
    assert "analytics" in purposes
    assert "marketing" not in purposes


@pytest.mark.asyncio
async def test_get_consent_history(consent_service):
    """Returns all records including revoked, ordered by created_at desc."""
    await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="marketing",
    )
    await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="analytics",
    )
    await consent_service.revoke(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="marketing",
    )

    history = await consent_service.get_consent_history(
        tenant_id=TENANT, subject_id=SUBJECT,
    )
    assert len(history) == 2
    # Should contain both granted and revoked records
    purposes = {r["purpose"] for r in history}
    assert purposes == {"marketing", "analytics"}
    # The revoked one should have revoked_at set
    marketing = [r for r in history if r["purpose"] == "marketing"][0]
    assert marketing["granted"] is False
    assert marketing["revoked_at"] is not None


@pytest.mark.asyncio
async def test_regrant_after_revoke(consent_service):
    """Revoking then granting again creates a new record; old one retained."""
    first = await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="essential",
    )
    await consent_service.revoke(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="essential",
    )
    second = await consent_service.grant(
        tenant_id=TENANT, subject_id=SUBJECT, purpose="essential",
    )

    # Different record IDs
    assert first["id"] != second["id"]
    assert second["granted"] is True

    # History should show both records
    history = await consent_service.get_consent_history(
        tenant_id=TENANT, subject_id=SUBJECT,
    )
    assert len(history) == 2
    granted_records = [r for r in history if r["granted"] is True]
    revoked_records = [r for r in history if r["granted"] is False]
    assert len(granted_records) == 1
    assert len(revoked_records) == 1


@pytest.mark.asyncio
async def test_consent_gated_route_rejection(test_db):
    """requires_consent dependency rejects when no active consent exists."""
    from fastapi import HTTPException

    checker = requires_consent("marketing")

    # Build a mock request with app.state.db
    mock_request = MagicMock()
    mock_request.app.state.db = test_db

    user = {"user_id": "user-999", "tenant_id": "tenant-999", "username": "testuser"}

    with pytest.raises(HTTPException) as exc_info:
        await checker(request=mock_request, user=user)

    assert exc_info.value.status_code == 403
    assert "Consent required" in exc_info.value.detail
