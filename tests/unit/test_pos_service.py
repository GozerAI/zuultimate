"""Unit tests for POSService."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.pos.service import POSService


@pytest.fixture
def svc(test_db):
    return POSService(test_db)


# ---------------------------------------------------------------------------
# register_terminal
# ---------------------------------------------------------------------------


async def test_register_terminal_success(svc):
    result = await svc.register_terminal("POS-1", location="Store A", device_type="kiosk")
    assert result["name"] == "POS-1"
    assert result["location"] == "Store A"
    assert result["is_active"] is True
    assert "id" in result


async def test_register_terminal_empty_name_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.register_terminal("")


async def test_register_terminal_defaults(svc):
    result = await svc.register_terminal("POS-2")
    assert result["location"] == ""
    assert result["device_type"] == ""


# ---------------------------------------------------------------------------
# create_transaction
# ---------------------------------------------------------------------------


async def test_create_transaction_success(svc):
    terminal = await svc.register_terminal("T1")
    result = await svc.create_transaction(terminal["id"], 50.0)
    assert result["status"] == "completed"
    assert result["reference"].startswith("TXN-")
    assert result["amount"] == 50.0
    assert result["currency"] == "USD"


async def test_create_transaction_nonexistent_terminal(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.create_transaction("nonexistent", 10.0)


async def test_create_transaction_zero_amount(svc):
    with pytest.raises(ValidationError, match="positive"):
        terminal = await svc.register_terminal("T2")
        await svc.create_transaction(terminal["id"], 0)


async def test_create_transaction_negative_amount(svc):
    with pytest.raises(ValidationError, match="positive"):
        terminal = await svc.register_terminal("T3")
        await svc.create_transaction(terminal["id"], -10.0)


# ---------------------------------------------------------------------------
# fraud detection
# ---------------------------------------------------------------------------


async def test_fraud_alert_created_for_high_amount(svc):
    terminal = await svc.register_terminal("T-fraud")
    await svc.create_transaction(terminal["id"], 15_000.0)
    alerts = await svc.get_fraud_alerts()
    assert len(alerts) >= 1
    types = {a["alert_type"] for a in alerts}
    assert "high_amount" in types


async def test_no_fraud_alert_below_threshold(svc):
    terminal = await svc.register_terminal("T-safe")
    await svc.create_transaction(terminal["id"], 9_999.0)
    alerts = await svc.get_fraud_alerts()
    assert len(alerts) == 0


async def test_fraud_alerts_filter_resolved(svc):
    terminal = await svc.register_terminal("T-filter")
    await svc.create_transaction(terminal["id"], 20_000.0)
    unresolved = await svc.get_fraud_alerts(resolved=False)
    assert len(unresolved) >= 1
    resolved = await svc.get_fraud_alerts(resolved=True)
    assert len(resolved) == 0


async def test_fraud_alerts_empty_list(svc):
    alerts = await svc.get_fraud_alerts()
    assert alerts == []
