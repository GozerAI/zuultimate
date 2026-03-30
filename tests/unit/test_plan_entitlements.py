"""Tests for PLAN_ENTITLEMENTS and LicenseGate interaction with plan features."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from zuultimate.common.config import PLAN_ENTITLEMENTS
from zuultimate.common.licensing import ZuulLicenseGate


# ---------------------------------------------------------------------------
# Plan existence
# ---------------------------------------------------------------------------


def test_starter_plan_exists():
    assert "starter" in PLAN_ENTITLEMENTS


def test_pro_plan_exists():
    assert "pro" in PLAN_ENTITLEMENTS


def test_business_plan_exists():
    assert "business" in PLAN_ENTITLEMENTS


# ---------------------------------------------------------------------------
# Plan superset relationships
# ---------------------------------------------------------------------------


def _extract_products(features: list[str]) -> set[str]:
    """Extract product names (portion before ':') from a feature list."""
    products = set()
    for f in features:
        if ":" in f:
            products.add(f.split(":")[0])
        else:
            products.add(f)
    return products


def test_plans_are_superset():
    """Pro includes all starter products; business includes all pro products."""
    starter_products = _extract_products(PLAN_ENTITLEMENTS["starter"])
    pro_products = _extract_products(PLAN_ENTITLEMENTS["pro"])
    business_products = _extract_products(PLAN_ENTITLEMENTS["business"])

    assert starter_products.issubset(pro_products), (
        f"Pro plan missing starter products: {starter_products - pro_products}"
    )
    assert pro_products.issubset(business_products), (
        f"Business plan missing pro products: {pro_products - business_products}"
    )


# ---------------------------------------------------------------------------
# All plans have product entries for known products
# ---------------------------------------------------------------------------

_KNOWN_PRODUCTS = {"trendscope", "shopforge", "brandguard", "taskpilot"}


def test_all_plans_have_product_entries():
    for plan_name, features in PLAN_ENTITLEMENTS.items():
        products = _extract_products(features)
        for product in _KNOWN_PRODUCTS:
            assert product in products, (
                f"Plan '{plan_name}' missing product '{product}'"
            )


# ---------------------------------------------------------------------------
# LicenseGate feature checks
# ---------------------------------------------------------------------------


def _make_gate(features: list[str]) -> ZuulLicenseGate:
    gate = ZuulLicenseGate(license_key="TEST-KEY", server_url="http://test")
    mock_client = MagicMock()
    mock_result = MagicMock()
    mock_result.valid = True
    mock_result.features = features
    mock_client.validate.return_value = mock_result
    gate._client = mock_client
    return gate


def test_license_gate_check_feature():
    gate = _make_gate(["zul.sso.oidc", "zul.rbac.matrix"])
    assert gate.check_feature("zul.sso.oidc") is True
    assert gate.check_feature("zul.rbac.matrix") is True


def test_license_gate_blocks_missing_feature():
    gate = _make_gate(["zul.sso.oidc"])
    assert gate.check_feature("zul.gateway.middleware") is False
    assert gate.check_feature("nonexistent.feature") is False


def test_license_gate_plan_upgrade():
    """Simulates a plan upgrade by switching features."""
    gate = _make_gate(["zul.sso.oidc"])
    assert gate.check_feature("zul.gateway.middleware") is False

    # "Upgrade" — replace features and clear cache
    gate._features_cache = None
    mock_result = MagicMock()
    mock_result.valid = True
    mock_result.features = ["zul.sso.oidc", "zul.gateway.middleware"]
    gate._client.validate.return_value = mock_result

    assert gate.check_feature("zul.gateway.middleware") is True


# ---------------------------------------------------------------------------
# No duplicate features within a single plan
# ---------------------------------------------------------------------------


def test_no_duplicate_features():
    for plan_name, features in PLAN_ENTITLEMENTS.items():
        assert len(features) == len(set(features)), (
            f"Plan '{plan_name}' has duplicate features"
        )
