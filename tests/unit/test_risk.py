"""Unit tests for risk signal aggregator (Phase 3.1)."""

import pytest

from zuultimate.common.redis import RedisManager
from zuultimate.identity.risk.evaluator import RiskEvaluator
from zuultimate.identity.risk.models import RiskAction, RiskDecision, RiskSignal
from zuultimate.identity.risk.signals import (
    GeoAnomalySignal,
    NewDeviceSignal,
    VelocitySignal,
)


@pytest.fixture
def redis():
    """RedisManager with in-memory fallback (no real Redis)."""
    mgr = RedisManager()
    mgr._available = False
    return mgr


def _context(
    ip_hash="iphash1",
    user_hash="userhash1",
    device_hash="devhash1",
    country_code="US",
):
    return {
        "ip_hash": ip_hash,
        "user_hash": user_hash,
        "device_hash": device_hash,
        "country_code": country_code,
    }


# ── VelocitySignal ──


async def test_velocity_signal_low_traffic(redis):
    """Under threshold returns score 0.0."""
    signal = VelocitySignal(redis)
    for _ in range(4):
        result = await signal.evaluate(_context())
    assert result.score == 0.0
    assert result.signal_type == "velocity"


async def test_velocity_signal_high_traffic(redis):
    """Over 5 attempts in 60 s returns score 0.7 (step-up level)."""
    signal = VelocitySignal(redis)
    for _ in range(6):
        result = await signal.evaluate(_context())
    assert result.score == 0.7
    assert result.signal_type == "velocity"
    assert result.evidence["count"] == 6


async def test_velocity_signal_block_level(redis):
    """Over 15 attempts in 60 s returns score 0.9 (block level)."""
    signal = VelocitySignal(redis)
    for _ in range(16):
        result = await signal.evaluate(_context())
    assert result.score == 0.9
    assert result.evidence["count"] == 16


# ── NewDeviceSignal ──


async def test_new_device_signal_first_time(redis):
    """Unknown device returns score 0.4."""
    signal = NewDeviceSignal(redis)
    result = await signal.evaluate(_context())
    assert result.score == 0.4
    assert result.signal_type == "new_device"


async def test_new_device_signal_known(redis):
    """Known device returns score 0.0."""
    signal = NewDeviceSignal(redis)
    # First call registers the device
    await signal.evaluate(_context())
    # Second call should recognize it
    result = await signal.evaluate(_context())
    assert result.score == 0.0


# ── GeoAnomalySignal ──


async def test_geo_anomaly_new_country(redis):
    """Unknown country returns score 0.5."""
    signal = GeoAnomalySignal(redis)
    result = await signal.evaluate(_context(country_code="BR"))
    assert result.score == 0.5
    assert result.signal_type == "geo_anomaly"
    assert result.evidence["country_code"] == "BR"


async def test_geo_anomaly_known_country(redis):
    """Known country returns score 0.0."""
    signal = GeoAnomalySignal(redis)
    await signal.evaluate(_context(country_code="US"))
    result = await signal.evaluate(_context(country_code="US"))
    assert result.score == 0.0


# ── RiskEvaluator ──


async def test_evaluator_allow(redis):
    """All signals clear on second pass with same device/geo returns allow."""
    evaluator = RiskEvaluator(redis)
    # First call will trigger new_device + geo_anomaly but not velocity
    # Pre-seed device and geo so they are known
    ctx = _context()
    await redis.setex(f"risk:device:{ctx['user_hash']}:{ctx['device_hash']}", 86400, "1")
    await redis.setex(f"risk:geo:{ctx['user_hash']}:{ctx['country_code']}", 86400, "1")

    decision = await evaluator.evaluate(ctx)
    assert decision.action == RiskAction.allow
    assert decision.score == 0.0
    assert len(decision.signals) == 0


async def test_evaluator_step_up(redis):
    """Velocity above threshold triggers step_up (0.7 > 0.6)."""
    evaluator = RiskEvaluator(redis)
    ctx = _context()
    # Pre-seed device and geo to remove those signals
    await redis.setex(f"risk:device:{ctx['user_hash']}:{ctx['device_hash']}", 86400, "1")
    await redis.setex(f"risk:geo:{ctx['user_hash']}:{ctx['country_code']}", 86400, "1")

    # Generate 6 velocity hits (threshold is 5)
    key = f"risk:velocity:{ctx['ip_hash']}"
    for _ in range(5):
        await redis.sliding_window_add(key, 60)

    decision = await evaluator.evaluate(ctx)
    assert decision.action == RiskAction.step_up
    assert decision.score == 0.7


async def test_evaluator_block(redis):
    """Velocity at block level (>15) triggers block (0.9 > 0.85)."""
    evaluator = RiskEvaluator(redis)
    ctx = _context()
    # Pre-seed device and geo to remove those signals
    await redis.setex(f"risk:device:{ctx['user_hash']}:{ctx['device_hash']}", 86400, "1")
    await redis.setex(f"risk:geo:{ctx['user_hash']}:{ctx['country_code']}", 86400, "1")

    # Generate 15 velocity hits so the evaluate call makes 16 (> 15)
    key = f"risk:velocity:{ctx['ip_hash']}"
    for _ in range(15):
        await redis.sliding_window_add(key, 60)

    decision = await evaluator.evaluate(ctx)
    assert decision.action == RiskAction.block
    assert decision.score == 0.9


async def test_evaluator_new_device_triggers_signals(redis):
    """New device and new geo fire together, max is 0.5 (geo) -> allow since 0.5 < 0.6."""
    evaluator = RiskEvaluator(redis)
    # Fresh context, nothing pre-seeded — new device (0.4) + new geo (0.5)
    decision = await evaluator.evaluate(_context(country_code="JP"))
    # Max of 0.4 and 0.5 is 0.5 → allow
    assert decision.action == RiskAction.allow
    assert decision.score == 0.5
    assert len(decision.signals) == 2


async def test_risk_signal_dataclass():
    """RiskSignal defaults work correctly."""
    sig = RiskSignal(signal_type="test", score=0.5)
    assert sig.evidence == {}
    assert sig.score == 0.5


async def test_risk_decision_dataclass():
    """RiskDecision defaults work correctly."""
    dec = RiskDecision(action=RiskAction.allow, score=0.0)
    assert dec.signals == []
    assert dec.action == RiskAction.allow


async def test_sliding_window_add_returns_count(redis):
    """Verify RedisManager.sliding_window_add returns correct count."""
    count1 = await redis.sliding_window_add("sw:test", 60)
    assert count1 == 1
    count2 = await redis.sliding_window_add("sw:test", 60)
    assert count2 == 2
    count3 = await redis.sliding_window_add("sw:test", 60)
    assert count3 == 3
