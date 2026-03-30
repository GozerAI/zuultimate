"""Unit tests for enhanced POS fraud detection with pattern scoring."""

import pytest

from zuultimate.pos.service import POSService


@pytest.fixture
async def pos_svc(test_db):
    return POSService(test_db)


@pytest.fixture
async def terminal(pos_svc):
    result = await pos_svc.register_terminal(name="Test POS", location="Store 1")
    return result["id"]


async def test_normal_transaction_low_risk(pos_svc, terminal):
    result = await pos_svc.create_transaction(terminal, 50.99, "USD")
    assert result["risk_score"] == 0.0


async def test_high_amount_triggers_alert(pos_svc, terminal):
    result = await pos_svc.create_transaction(terminal, 15000.0, "USD")
    assert result["risk_score"] >= 0.4
    alerts = await pos_svc.get_fraud_alerts()
    high_amount_alerts = [a for a in alerts if a["alert_type"] == "high_amount"]
    assert len(high_amount_alerts) == 1


async def test_round_amount_triggers_alert(pos_svc, terminal):
    result = await pos_svc.create_transaction(terminal, 5000.0, "USD")
    assert result["risk_score"] >= 0.15
    alerts = await pos_svc.get_fraud_alerts()
    round_alerts = [a for a in alerts if a["alert_type"] == "round_amount"]
    assert len(round_alerts) == 1


async def test_currency_mismatch_triggers_alert(pos_svc, terminal):
    # First transaction sets the terminal's currency
    await pos_svc.create_transaction(terminal, 10.0, "USD")
    # Second with different currency
    result = await pos_svc.create_transaction(terminal, 10.0, "EUR")
    assert result["risk_score"] >= 0.2
    alerts = await pos_svc.get_fraud_alerts()
    mismatch_alerts = [a for a in alerts if a["alert_type"] == "currency_mismatch"]
    assert len(mismatch_alerts) == 1


async def test_combined_signals_stack(pos_svc, terminal):
    """High amount + round amount should combine scores."""
    result = await pos_svc.create_transaction(terminal, 20000.0, "USD")
    # high_amount (0.4) + round_amount (0.15) = 0.55
    assert result["risk_score"] >= 0.5
    alerts = await pos_svc.get_fraud_alerts()
    assert len(alerts) >= 2


async def test_risk_score_capped_at_1(pos_svc, terminal):
    """Risk score should not exceed 1.0."""
    # Create many transactions to trigger velocity
    for _ in range(7):
        await pos_svc.create_transaction(terminal, 10.0, "USD")
    # This one should have velocity signal
    result = await pos_svc.create_transaction(terminal, 50000.0, "EUR")
    assert result["risk_score"] <= 1.0


async def test_risk_score_in_response(pos_svc, terminal):
    result = await pos_svc.create_transaction(terminal, 25.0, "USD")
    assert "risk_score" in result
    assert isinstance(result["risk_score"], float)
