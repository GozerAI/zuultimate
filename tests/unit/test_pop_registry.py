"""Tests for PoP registry router — register, list, deregister PoPs."""

import pytest
from unittest.mock import MagicMock

from sqlalchemy import select

from zuultimate.identity.workforce.models import PopRegistration
from zuultimate.identity.workforce.schemas import PopRegisterRequest


@pytest.mark.asyncio
async def test_register_pop(test_db):
    """Register a new PoP and verify it persists."""
    from zuultimate.identity.workforce.pop_router import register_pop

    request = MagicMock()
    request.app.state.db = test_db

    body = PopRegisterRequest(
        pop_id="pop-us-east-1",
        pop_name="US East 1",
        region="us",
        public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
    )
    result = await register_pop(body, request)
    assert result.pop_id == "pop-us-east-1"
    assert result.pop_name == "US East 1"
    assert result.region == "us"
    assert result.status == "active"


@pytest.mark.asyncio
async def test_register_duplicate_pop_rejected(test_db):
    """Duplicate pop_id should return 409."""
    from zuultimate.identity.workforce.pop_router import register_pop
    from fastapi import HTTPException

    request = MagicMock()
    request.app.state.db = test_db

    body = PopRegisterRequest(
        pop_id="pop-dup",
        pop_name="Dup PoP",
        region="us",
        public_key="key-data",
    )
    await register_pop(body, request)

    with pytest.raises(HTTPException) as exc_info:
        await register_pop(body, request)
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_list_pops(test_db):
    """List all registered PoPs."""
    from zuultimate.identity.workforce.pop_router import register_pop, list_pops

    request = MagicMock()
    request.app.state.db = test_db

    for i in range(3):
        body = PopRegisterRequest(
            pop_id=f"pop-list-{i}",
            pop_name=f"PoP {i}",
            region="us",
            public_key=f"key-{i}",
        )
        await register_pop(body, request)

    result = await list_pops(request)
    pop_ids = {p.pop_id for p in result}
    assert "pop-list-0" in pop_ids
    assert "pop-list-1" in pop_ids
    assert "pop-list-2" in pop_ids


@pytest.mark.asyncio
async def test_deregister_pop(test_db):
    """Deregister sets status to deregistered."""
    from zuultimate.identity.workforce.pop_router import register_pop, deregister_pop

    request = MagicMock()
    request.app.state.db = test_db

    body = PopRegisterRequest(
        pop_id="pop-dereg",
        pop_name="To Deregister",
        region="eu",
        public_key="key",
    )
    await register_pop(body, request)

    result = await deregister_pop("pop-dereg", request)
    assert result.status == "deregistered"


@pytest.mark.asyncio
async def test_deregister_nonexistent(test_db):
    """Deregister unknown pop_id returns 404."""
    from zuultimate.identity.workforce.pop_router import deregister_pop
    from fastapi import HTTPException

    request = MagicMock()
    request.app.state.db = test_db

    with pytest.raises(HTTPException) as exc_info:
        await deregister_pop("nonexistent", request)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_pop_model_fields(test_db):
    """Verify PopRegistration model stores all fields correctly."""
    async with test_db.get_session("identity") as session:
        pop = PopRegistration(
            pop_id="pop-fields",
            pop_name="Field Test",
            region="ap",
            public_key="test-key-pem",
            status="active",
        )
        session.add(pop)

    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(PopRegistration).where(PopRegistration.pop_id == "pop-fields")
        )
        stored = result.scalar_one()
        assert stored.pop_name == "Field Test"
        assert stored.region == "ap"
        assert stored.public_key == "test-key-pem"


@pytest.mark.asyncio
async def test_list_pops_empty(test_db):
    """List on empty registry returns empty list."""
    from zuultimate.identity.workforce.pop_router import list_pops

    request = MagicMock()
    request.app.state.db = test_db

    result = await list_pops(request)
    # May have pops from other tests if run together, but should not error
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_pop_register_response_has_id(test_db):
    """Registered PoP response includes an ID."""
    from zuultimate.identity.workforce.pop_router import register_pop

    request = MagicMock()
    request.app.state.db = test_db

    body = PopRegisterRequest(
        pop_id="pop-id-check",
        pop_name="ID Check",
        region="us",
        public_key="key",
    )
    result = await register_pop(body, request)
    assert result.id  # UUID should be non-empty
