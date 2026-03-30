"""Unit tests for CRM provider adapter framework."""

import pytest
from unittest.mock import AsyncMock, patch

import httpx

from zuultimate.crm.adapters import (
    CRMAdapter,
    GenericAdapter,
    HubSpotAdapter,
    SalesforceAdapter,
    get_adapter,
    list_adapters,
    register_adapter,
)

_FAKE_REQUEST = httpx.Request("GET", "https://test.com")


def _resp(status: int = 200, json: dict | list | None = None) -> httpx.Response:
    """Build an httpx.Response with a request attached (needed for raise_for_status)."""
    return httpx.Response(status, json=json or {}, request=_FAKE_REQUEST)


# ---------------------------------------------------------------------------
# Salesforce adapter
# ---------------------------------------------------------------------------


class TestSalesforceAdapter:
    @pytest.fixture
    def adapter(self):
        return SalesforceAdapter(api_url="https://myorg.my.salesforce.com", api_key="test-token")

    async def test_test_connection_success(self, adapter):
        response = _resp(200)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.test_connection()
            assert result["connected"] is True
            assert result["provider"] == "salesforce"

    async def test_test_connection_failure(self, adapter):
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.test_connection()
            assert result["connected"] is False

    async def test_fetch_contacts_success(self, adapter):
        sf_response = {
            "records": [
                {"Id": "003xx1", "FirstName": "John", "LastName": "Doe", "Email": "john@sf.com"},
                {"Id": "003xx2", "FirstName": "Jane", "LastName": "Doe", "Email": "jane@sf.com"},
            ],
        }
        response = _resp(200, sf_response)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            contacts = await adapter.fetch_contacts(limit=10)
            assert len(contacts) == 2
            assert contacts[0]["Email"] == "john@sf.com"

    async def test_fetch_contacts_http_error(self, adapter):
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            contacts = await adapter.fetch_contacts()
            assert contacts == []

    async def test_push_contacts_success(self, adapter):
        sf_result = [{"success": True, "id": "003xx1"}, {"success": True, "id": "003xx2"}]
        response = _resp(200, sf_result)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.push_contacts([
                {"FirstName": "A", "LastName": "B", "Email": "a@b.com"},
                {"FirstName": "C", "LastName": "D", "Email": "c@d.com"},
            ])
            assert result["pushed"] == 2
            assert result["errors"] == 0

    async def test_push_contacts_partial_failure(self, adapter):
        sf_result = [{"success": True, "id": "003xx1"}, {"success": False, "errors": []}]
        response = _resp(200, sf_result)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.push_contacts([{"A": "1"}, {"B": "2"}])
            assert result["pushed"] == 1
            assert result["errors"] == 1

    def test_map_fields(self, adapter):
        record = {"FirstName": "John", "LastName": "Doe", "Email": "john@test.com"}
        mappings = {"FirstName": "first_name", "LastName": "last_name"}
        mapped = adapter.map_fields(record, mappings)
        assert mapped == {"first_name": "John", "last_name": "Doe"}

    def test_headers_include_bearer(self, adapter):
        headers = adapter._headers()
        assert headers["Authorization"] == "Bearer test-token"

    def test_base_url_includes_api_version(self, adapter):
        base = adapter._base()
        assert "/services/data/v59.0" in base


# ---------------------------------------------------------------------------
# HubSpot adapter
# ---------------------------------------------------------------------------


class TestHubSpotAdapter:
    @pytest.fixture
    def adapter(self):
        return HubSpotAdapter(api_url="https://api.hubapi.com", api_key="test-token")

    async def test_test_connection_success(self, adapter):
        response = _resp(200, {"results": []})
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.test_connection()
            assert result["connected"] is True
            assert result["provider"] == "hubspot"

    async def test_fetch_contacts_success(self, adapter):
        hs_response = {
            "results": [
                {"id": "101", "properties": {"firstname": "Alice", "lastname": "B", "email": "alice@hs.com"}},
                {"id": "102", "properties": {"firstname": "Bob", "lastname": "C", "email": "bob@hs.com"}},
            ],
        }
        response = _resp(200, hs_response)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            contacts = await adapter.fetch_contacts(limit=10)
            assert len(contacts) == 2
            assert contacts[0]["email"] == "alice@hs.com"
            assert contacts[0]["vid"] == "101"

    async def test_fetch_contacts_http_error(self, adapter):
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            contacts = await adapter.fetch_contacts()
            assert contacts == []

    async def test_push_contacts_success(self, adapter):
        hs_result = {"results": [{"id": "101"}, {"id": "102"}], "errors": []}
        response = _resp(200, hs_result)
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.push_contacts([{"email": "a@b.com"}])
            assert result["pushed"] == 2
            assert result["errors"] == 0

    def test_map_fields(self, adapter):
        record = {"firstname": "Alice", "lastname": "B"}
        mapped = adapter.map_fields(record, {"firstname": "first_name"})
        assert mapped == {"first_name": "Alice"}


# ---------------------------------------------------------------------------
# Generic adapter
# ---------------------------------------------------------------------------


class TestGenericAdapter:
    @pytest.fixture
    def adapter(self):
        return GenericAdapter(api_url="https://webhook.example.com/contacts")

    async def test_fetch_returns_empty(self, adapter):
        contacts = await adapter.fetch_contacts()
        assert contacts == []

    async def test_push_contacts_success(self, adapter):
        response = _resp(200, {"ok": True})
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.push_contacts([{"name": "Test"}])
            assert result["pushed"] == 1

    async def test_push_contacts_http_error(self, adapter):
        with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await adapter.push_contacts([{"name": "Test"}])
            assert result["pushed"] == 0
            assert "error" in result


# ---------------------------------------------------------------------------
# Factory / registry
# ---------------------------------------------------------------------------


def test_get_adapter_salesforce():
    adapter = get_adapter("salesforce", "https://sf.com", "token")
    assert isinstance(adapter, SalesforceAdapter)


def test_get_adapter_hubspot():
    adapter = get_adapter("hubspot", "https://hs.com")
    assert isinstance(adapter, HubSpotAdapter)


def test_get_adapter_unknown():
    with pytest.raises(ValueError, match="Unknown CRM provider"):
        get_adapter("unknown_provider", "https://x.com")


def test_list_adapters():
    adapters = list_adapters()
    assert "salesforce" in adapters
    assert "hubspot" in adapters
    assert "generic" in adapters


def test_register_custom_adapter():
    class CustomAdapter(CRMAdapter):
        name = "custom"

        async def test_connection(self):
            return {"connected": True}

        async def fetch_contacts(self, limit=100, offset=0):
            return []

        async def push_contacts(self, contacts):
            return {"pushed": 0}

        def map_fields(self, record, mappings):
            return {}

    register_adapter("custom", CustomAdapter)
    adapter = get_adapter("custom", "https://custom.com")
    assert isinstance(adapter, CustomAdapter)


def test_url_trailing_slash_stripped():
    adapter = SalesforceAdapter(api_url="https://sf.com/", api_key="x")
    assert not adapter.api_url.endswith("/")
