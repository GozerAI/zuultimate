"""Unit tests for idempotency key service."""

import pytest

from zuultimate.common.idempotency import IdempotencyService


@pytest.fixture
async def idem_svc(test_db):
    return IdempotencyService(test_db)


async def test_store_and_get_cached(idem_svc):
    await idem_svc.store("key-1", "/test", 200, {"result": "ok"})
    cached = await idem_svc.get_cached("key-1")
    assert cached is not None
    assert cached["status_code"] == 200
    assert cached["body"] == {"result": "ok"}


async def test_get_cached_returns_none_for_unknown_key(idem_svc):
    result = await idem_svc.get_cached("nonexistent")
    assert result is None


async def test_same_key_returns_same_response(idem_svc):
    await idem_svc.store("key-2", "/test", 201, {"id": "abc"})
    first = await idem_svc.get_cached("key-2")
    second = await idem_svc.get_cached("key-2")
    assert first == second


async def test_different_keys_independent(idem_svc):
    await idem_svc.store("key-a", "/test", 200, {"a": True})
    await idem_svc.store("key-b", "/test", 201, {"b": True})
    a = await idem_svc.get_cached("key-a")
    b = await idem_svc.get_cached("key-b")
    assert a["body"] == {"a": True}
    assert b["body"] == {"b": True}
