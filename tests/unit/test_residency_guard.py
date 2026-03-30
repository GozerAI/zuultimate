"""Unit tests for ResidencyViolationGuard and residency helpers (Phase A.2)."""

import json

import pytest

from zuultimate.common.residency import (
    GLOBAL_TABLES,
    SOVEREIGN_TABLES,
    ReplicationPolicy,
    ResidencyViolationError,
    ResidencyViolationGuard,
    get_replication_policy,
)


# ---------------------------------------------------------------------------
# get_replication_policy helpers
# ---------------------------------------------------------------------------


def test_sovereign_tables_return_sovereign_policy():
    for table in SOVEREIGN_TABLES:
        assert get_replication_policy(table) == ReplicationPolicy.SOVEREIGN_RING_ONLY


def test_global_tables_return_global_policy():
    for table in GLOBAL_TABLES:
        assert get_replication_policy(table) == ReplicationPolicy.CONTROL_PLANE_GLOBAL


def test_unknown_table_defaults_to_global():
    """Any table not in the sovereign set defaults to CONTROL_PLANE_GLOBAL."""
    assert get_replication_policy("some_random_table") == ReplicationPolicy.CONTROL_PLANE_GLOBAL
    assert get_replication_policy("audit_logs") == ReplicationPolicy.CONTROL_PLANE_GLOBAL


# ---------------------------------------------------------------------------
# ResidencyViolationGuard.check_write_allowed
# ---------------------------------------------------------------------------


def test_global_table_always_allowed_regardless_of_ring():
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    assert guard.check_write_allowed("tenants", "eu") is True
    assert guard.check_write_allowed("roles", "ap") is True
    assert guard.check_write_allowed("api_keys", "us") is True


def test_sovereign_table_allowed_when_rings_match():
    guard = ResidencyViolationGuard(current_region="eu", current_ring="eu")
    assert guard.check_write_allowed("users", "eu") is True
    assert guard.check_write_allowed("credentials", "eu") is True


def test_sovereign_table_blocked_when_rings_differ():
    """Writing a sovereign table in a ring that doesn't match is not allowed."""
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    assert guard.check_write_allowed("users", "eu") is False
    assert guard.check_write_allowed("user_sessions", "ap") is False
    assert guard.check_write_allowed("auth_events", "eu") is False
    assert guard.check_write_allowed("mfa_devices", "eu") is False


def test_sovereign_table_allowed_with_global_ring():
    """A tenant with sovereignty_ring='global' imposes no restriction."""
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    assert guard.check_write_allowed("users", "global") is True


def test_sovereign_table_allowed_when_ring_is_none():
    """None sovereignty_ring (legacy tenants) is treated as unrestricted."""
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    assert guard.check_write_allowed("users", None) is True


# ---------------------------------------------------------------------------
# ResidencyViolationGuard.validate_pii_region
# ---------------------------------------------------------------------------


def test_pii_region_valid_when_in_allowed_list():
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    json_str = json.dumps(["us", "eu"])
    assert guard.validate_pii_region(json_str, "us") is True
    assert guard.validate_pii_region(json_str, "eu") is True


def test_pii_region_invalid_when_not_in_allowed_list():
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    json_str = json.dumps(["us"])
    assert guard.validate_pii_region(json_str, "eu") is False
    assert guard.validate_pii_region(json_str, "ap") is False


def test_pii_region_fallback_on_bad_json():
    """Malformed JSON falls back to [current_ring]; only current_ring is allowed."""
    guard = ResidencyViolationGuard(current_region="eu", current_ring="eu")
    assert guard.validate_pii_region("not-valid-json", "eu") is True
    assert guard.validate_pii_region("not-valid-json", "us") is False


def test_pii_region_fallback_on_none_input():
    """None input falls back to [current_ring]."""
    guard = ResidencyViolationGuard(current_region="us", current_ring="us")
    assert guard.validate_pii_region(None, "us") is True  # type: ignore[arg-type]
    assert guard.validate_pii_region(None, "eu") is False  # type: ignore[arg-type]


def test_pii_region_single_region_list():
    guard = ResidencyViolationGuard(current_region="ap", current_ring="ap")
    json_str = json.dumps(["ap"])
    assert guard.validate_pii_region(json_str, "ap") is True
    assert guard.validate_pii_region(json_str, "us") is False


# ---------------------------------------------------------------------------
# ResidencyViolationError is an Exception
# ---------------------------------------------------------------------------


def test_residency_violation_error_is_exception():
    err = ResidencyViolationError("Ring mismatch")
    assert isinstance(err, Exception)
    assert str(err) == "Ring mismatch"
