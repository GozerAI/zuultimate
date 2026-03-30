"""Unit tests for POS settlement and reconciliation."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.pos.service import POSService


@pytest.fixture
def svc(test_db):
    return POSService(test_db)


async def test_create_settlement(svc):
    terminal = await svc.register_terminal("T1")
    await svc.create_transaction(terminal["id"], 100.0)
    await svc.create_transaction(terminal["id"], 200.0)

    result = await svc.create_settlement(terminal["id"])
    assert result["transaction_count"] == 2
    assert result["total_amount"] == 300.0
    assert result["status"] == "settled"
    assert result["reference"].startswith("STL-")


async def test_settlement_marks_txns_as_settled(svc):
    terminal = await svc.register_terminal("T2")
    await svc.create_transaction(terminal["id"], 50.0)
    await svc.create_settlement(terminal["id"])

    # No more unsettled transactions
    with pytest.raises(ValidationError, match="No unsettled"):
        await svc.create_settlement(terminal["id"])


async def test_settlement_nonexistent_terminal(svc):
    with pytest.raises(NotFoundError):
        await svc.create_settlement("nonexistent")


async def test_settlement_no_transactions(svc):
    terminal = await svc.register_terminal("T3")
    with pytest.raises(ValidationError, match="No unsettled"):
        await svc.create_settlement(terminal["id"])


async def test_get_settlement(svc):
    terminal = await svc.register_terminal("T4")
    await svc.create_transaction(terminal["id"], 75.0)
    settlement = await svc.create_settlement(terminal["id"])

    result = await svc.get_settlement(settlement["id"])
    assert result["total_amount"] == 75.0


async def test_get_settlement_not_found(svc):
    with pytest.raises(NotFoundError):
        await svc.get_settlement("nonexistent")


async def test_reconcile_matches(svc):
    terminal = await svc.register_terminal("T5")
    await svc.create_transaction(terminal["id"], 100.0)
    await svc.create_transaction(terminal["id"], 200.0)
    await svc.create_settlement(terminal["id"])

    result = await svc.reconcile(terminal["id"])
    assert result["reconciled"] is True
    assert result["discrepancy"] == 0.0
    assert result["batch_total"] == 300.0
    assert result["transaction_total"] == 300.0


async def test_reconcile_empty(svc):
    terminal = await svc.register_terminal("T6")
    result = await svc.reconcile(terminal["id"])
    assert result["reconciled"] is True
    assert result["batch_total"] == 0.0
