"""CRM provider adapter framework — pluggable sync backends."""

from abc import ABC, abstractmethod

import httpx

from zuultimate.common.logging import get_logger

logger = get_logger(__name__)


class CRMAdapter(ABC):
    """Base class for CRM provider adapters."""

    name: str = "base"

    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test the connection to the CRM provider."""
        ...

    @abstractmethod
    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """Fetch contacts from the CRM provider."""
        ...

    @abstractmethod
    async def push_contacts(self, contacts: list[dict]) -> dict:
        """Push contacts to the CRM provider."""
        ...

    @abstractmethod
    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        """Transform record fields using the mapping configuration."""
        ...


class SalesforceAdapter(CRMAdapter):
    """Salesforce CRM adapter using the Salesforce REST API.

    Expects ``api_url`` to be the Salesforce instance URL (e.g.
    ``https://myorg.my.salesforce.com``) and ``api_key`` to be an
    OAuth2 Bearer access token.

    The ``/services/data/v59.0/`` API version prefix is appended
    automatically.
    """

    name = "salesforce"
    _API_VERSION = "v59.0"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _base(self) -> str:
        return f"{self.api_url}/services/data/{self._API_VERSION}"

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(
                    f"{self._base()}/", headers=self._headers(),
                )
                resp.raise_for_status()
                return {"connected": True, "provider": "salesforce", "api_url": self.api_url}
            except httpx.HTTPError as exc:
                return {"connected": False, "provider": "salesforce", "error": str(exc)}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        query = (
            f"SELECT Id, FirstName, LastName, Email "
            f"FROM Contact "
            f"ORDER BY LastModifiedDate DESC "
            f"LIMIT {limit} OFFSET {offset}"
        )
        url = f"{self._base()}/query"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    url, params={"q": query}, headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("records", [])
            except httpx.HTTPError as exc:
                logger.error("Salesforce fetch_contacts failed: %s", exc)
                return []

    async def push_contacts(self, contacts: list[dict]) -> dict:
        url = f"{self._base()}/composite/sobjects"
        records = []
        for c in contacts:
            record = {"attributes": {"type": "Contact"}}
            record.update(c)
            records.append(record)

        payload = {"allOrNone": False, "records": records}
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(
                    url, json=payload, headers=self._headers(),
                )
                resp.raise_for_status()
                results = resp.json()
                success = sum(1 for r in results if r.get("success"))
                return {
                    "pushed": success,
                    "errors": len(results) - success,
                    "provider": "salesforce",
                }
            except httpx.HTTPError as exc:
                logger.error("Salesforce push_contacts failed: %s", exc)
                return {"pushed": 0, "errors": len(contacts), "provider": "salesforce", "error": str(exc)}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


class HubSpotAdapter(CRMAdapter):
    """HubSpot CRM adapter using the HubSpot CRM API v3.

    Expects ``api_url`` to default to ``https://api.hubapi.com``
    and ``api_key`` to be a HubSpot private app access token.
    """

    name = "hubspot"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict:
        url = f"{self.api_url}/crm/v3/objects/contacts"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(
                    url, params={"limit": 1}, headers=self._headers(),
                )
                resp.raise_for_status()
                return {"connected": True, "provider": "hubspot", "api_url": self.api_url}
            except httpx.HTTPError as exc:
                return {"connected": False, "provider": "hubspot", "error": str(exc)}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        url = f"{self.api_url}/crm/v3/objects/contacts"
        params = {
            "limit": min(limit, 100),  # HubSpot max per page
            "properties": "firstname,lastname,email",
        }
        if offset > 0:
            params["after"] = str(offset)

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url, params=params, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                results = []
                for item in data.get("results", []):
                    props = item.get("properties", {})
                    results.append({
                        "vid": item.get("id", ""),
                        "firstname": props.get("firstname", ""),
                        "lastname": props.get("lastname", ""),
                        "email": props.get("email", ""),
                    })
                return results
            except httpx.HTTPError as exc:
                logger.error("HubSpot fetch_contacts failed: %s", exc)
                return []

    async def push_contacts(self, contacts: list[dict]) -> dict:
        url = f"{self.api_url}/crm/v3/objects/contacts/batch/create"
        inputs = []
        for c in contacts:
            inputs.append({"properties": c})

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(
                    url, json={"inputs": inputs}, headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                created = len(data.get("results", []))
                errors = len(data.get("errors", []))
                return {"pushed": created, "errors": errors, "provider": "hubspot"}
            except httpx.HTTPError as exc:
                logger.error("HubSpot push_contacts failed: %s", exc)
                return {"pushed": 0, "errors": len(contacts), "provider": "hubspot", "error": str(exc)}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


class GenericAdapter(CRMAdapter):
    """Generic/webhook-based CRM adapter.

    Sends contacts as JSON POST to the configured ``api_url``.
    Fetching is not supported (returns empty list) since generic
    integrations typically push via webhooks.
    """

    name = "generic"

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(self.api_url)
                return {"connected": resp.is_success, "provider": "generic", "api_url": self.api_url}
            except httpx.HTTPError:
                return {"connected": False, "provider": "generic", "api_url": self.api_url}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return []  # Generic adapter doesn't support fetching

    async def push_contacts(self, contacts: list[dict]) -> dict:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(
                    self.api_url, json={"contacts": contacts}, headers=headers,
                )
                resp.raise_for_status()
                return {"pushed": len(contacts), "provider": "generic"}
            except httpx.HTTPError as exc:
                logger.error("Generic push_contacts failed: %s", exc)
                return {"pushed": 0, "errors": len(contacts), "provider": "generic", "error": str(exc)}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


# Adapter registry
_ADAPTERS: dict[str, type[CRMAdapter]] = {
    "salesforce": SalesforceAdapter,
    "hubspot": HubSpotAdapter,
    "generic": GenericAdapter,
}


def get_adapter(provider: str, api_url: str, api_key: str = "") -> CRMAdapter:
    """Factory function to create a CRM adapter by provider name."""
    adapter_cls = _ADAPTERS.get(provider.lower())
    if adapter_cls is None:
        raise ValueError(f"Unknown CRM provider: {provider}. Available: {list(_ADAPTERS.keys())}")
    return adapter_cls(api_url=api_url, api_key=api_key)


def list_adapters() -> list[str]:
    """Return all registered adapter names."""
    return list(_ADAPTERS.keys())


def register_adapter(name: str, adapter_cls: type[CRMAdapter]) -> None:
    """Register a custom CRM adapter."""
    _ADAPTERS[name.lower()] = adapter_cls
