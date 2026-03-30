"""Tests for the Zuultimate Python SDK stub."""

import sys
import os
import time

import pytest

# Add SDK to path so we can import without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from zuultimate_sdk.auth import TokenManager
from zuultimate_sdk.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    ZuultimateError,
)
from zuultimate_sdk.models import (
    HealthStatus,
    IntrospectResult,
    Tenant,
    TenantProvisionResult,
    TokenPair,
    User,
)


class TestTokenManager:
    def test_token_manager_set_and_get(self):
        tm = TokenManager()
        tm.set_tokens("access123", "refresh456", 3600)

        assert tm.access_token == "access123"
        assert tm.refresh_token == "refresh456"
        assert tm.needs_refresh is False

    def test_token_manager_expiry(self):
        tm = TokenManager()
        # Set tokens with 0 seconds expiry (minus 30s buffer means already expired)
        tm.set_tokens("access123", "refresh456", 0)

        assert tm.access_token is None
        assert tm.refresh_token == "refresh456"
        assert tm.needs_refresh is True

    def test_token_manager_clear(self):
        tm = TokenManager()
        tm.set_tokens("access123", "refresh456", 3600)
        tm.clear()

        assert tm.access_token is None
        assert tm.refresh_token is None
        assert tm.needs_refresh is False


class TestExceptions:
    def test_exception_hierarchy(self):
        assert issubclass(AuthenticationError, ZuultimateError)
        assert issubclass(NotFoundError, ZuultimateError)
        assert issubclass(ValidationError, ZuultimateError)
        assert issubclass(RateLimitError, ZuultimateError)
        assert issubclass(ZuultimateError, Exception)

    def test_exception_attributes(self):
        err = ZuultimateError("test error", status_code=500, code="INTERNAL")
        assert err.message == "test error"
        assert err.status_code == 500
        assert err.code == "INTERNAL"
        assert str(err) == "test error"

    def test_authentication_error(self):
        err = AuthenticationError("bad creds", 401)
        assert isinstance(err, ZuultimateError)
        assert err.status_code == 401


class TestModels:
    def test_token_pair_parse(self):
        pair = TokenPair(
            access_token="abc",
            refresh_token="def",
            token_type="bearer",
            expires_in=3600,
        )
        assert pair.access_token == "abc"
        assert pair.token_type == "bearer"
        assert pair.expires_in == 3600

    def test_user_parse(self):
        user = User(
            id="u1",
            email="test@example.com",
            username="testuser",
            display_name="Test User",
            is_active=True,
            is_verified=False,
            tenant_id="t1",
        )
        assert user.id == "u1"
        assert user.tenant_id == "t1"

    def test_user_optional_tenant(self):
        user = User(
            id="u2",
            email="test@example.com",
            username="testuser",
            display_name="Test",
            is_active=True,
            is_verified=True,
        )
        assert user.tenant_id is None

    def test_tenant_parse(self):
        tenant = Tenant(
            id="t1",
            name="Acme Corp",
            slug="acme",
            is_active=True,
            plan="pro",
            status="active",
        )
        assert tenant.slug == "acme"
        assert tenant.plan == "pro"

    def test_provision_result_parse(self):
        result = TenantProvisionResult(
            tenant_id="t1",
            user_id="u1",
            api_key="gzr_test",
            plan="starter",
            entitlements=["trendscope:basic"],
        )
        assert result.api_key == "gzr_test"
        assert "trendscope:basic" in result.entitlements

    def test_introspect_result_parse(self):
        result = IntrospectResult(active=True, sub="u1", username="admin")
        assert result.active is True
        assert result.sub == "u1"
        assert result.tenant_id is None

    def test_introspect_inactive(self):
        result = IntrospectResult(active=False)
        assert result.active is False
        assert result.sub is None

    def test_health_status_parse(self):
        health = HealthStatus(status="healthy", version="1.0.0", environment="test")
        assert health.status == "healthy"
