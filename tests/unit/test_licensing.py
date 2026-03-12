"""Tests for zuultimate.common.licensing — ZuulLicenseGate."""

from unittest.mock import MagicMock, patch

import pytest

from zuultimate.common.licensing import PRICING_URL, ZuulLicenseGate


class TestCommunityMode:
    def test_no_key_blocks_all(self):
        gate = ZuulLicenseGate(license_key="")
        assert gate.is_community_mode is True
        assert gate.check_feature("zul.gateway.middleware") is False

    def test_no_key_gate_raises(self):
        gate = ZuulLicenseGate(license_key="")
        with pytest.raises(PermissionError):
            gate.gate("zul.gateway.middleware")


class TestWithValidKey:
    def _make_gate(self, features):
        gate = ZuulLicenseGate(license_key="TEST-KEY", server_url="http://test")
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.valid = True
        mock_result.features = features
        mock_client.validate.return_value = mock_result
        gate._client = mock_client
        return gate

    def test_entitled_feature_allowed(self):
        gate = self._make_gate(["zul.gateway.middleware", "zul.sso.oidc"])
        assert gate.check_feature("zul.gateway.middleware") is True

    def test_unentitled_feature_blocked(self):
        gate = self._make_gate(["zul.sso.oidc"])
        assert gate.check_feature("zul.gateway.middleware") is False

    def test_gate_raises_permission_error(self):
        gate = self._make_gate(["zul.sso.oidc"])
        with pytest.raises(PermissionError, match="Enterprise license"):
            gate.gate("zul.gateway.middleware")

    def test_gate_error_includes_pricing_url(self):
        gate = self._make_gate(["zul.sso.oidc"])
        with pytest.raises(PermissionError, match=PRICING_URL):
            gate.gate("zul.gateway.middleware")

    def test_decorator_raises_on_blocked(self):
        gate = self._make_gate(["zul.sso.oidc"])

        @gate.require_feature("zul.gateway.middleware")
        def my_func():
            return "ok"

        with pytest.raises(PermissionError, match="AI Security Gateway"):
            my_func()

    def test_decorator_allows_entitled(self):
        gate = self._make_gate(["zul.gateway.middleware"])

        @gate.require_feature("zul.gateway.middleware")
        def my_func():
            return "ok"

        assert my_func() == "ok"


class TestFailClosed:
    def test_connection_error_blocks(self):
        gate = ZuulLicenseGate(license_key="TEST-KEY")
        mock_client = MagicMock()
        mock_client.validate.side_effect = Exception("connection refused")
        gate._client = mock_client
        assert gate.check_feature("zul.gateway.middleware") is False

    def test_import_error_blocks(self):
        gate = ZuulLicenseGate(license_key="TEST-KEY")
        with patch.object(gate, '_get_client', return_value=None):
            assert gate.check_feature("zul.gateway.middleware") is False


class TestCaching:
    def test_uses_cache_within_ttl(self):
        gate = ZuulLicenseGate(license_key="TEST-KEY", cache_ttl=60)
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.valid = True
        mock_result.features = ["zul.sso.oidc"]
        mock_client.validate.return_value = mock_result
        gate._client = mock_client

        gate.check_feature("zul.sso.oidc")
        gate.check_feature("zul.sso.oidc")

        assert mock_client.validate.call_count == 1
