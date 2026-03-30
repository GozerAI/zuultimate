"""Typed HTTP clients for the Zuultimate API."""

import httpx

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


class AsyncZuultimateClient:
    """Async client for the Zuultimate identity platform API."""

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._tokens = TokenManager()

    def _headers(self) -> dict:
        """Build authorization headers from API key or managed token."""
        if self._api_key:
            return {"Authorization": f"Bearer {self._api_key}"}
        token = self._tokens.access_token
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        """Raise a typed exception for non-2xx responses."""
        if resp.status_code == 401:
            raise AuthenticationError("Authentication failed", 401)
        if resp.status_code == 404:
            raise NotFoundError("Resource not found", 404)
        if resp.status_code == 422:
            raise ValidationError(resp.json().get("error", "Validation failed"), 422)
        if resp.status_code == 429:
            raise RateLimitError("Rate limited", 429)
        if resp.status_code >= 400:
            raise ZuultimateError(f"HTTP {resp.status_code}", resp.status_code)

    # -- Auth --
    async def login(self, username: str, password: str) -> TokenPair:
        """Authenticate with username and password, returning a token pair."""
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.post(
                f"{self.base_url}/v1/identity/login",
                json={"username": username, "password": password},
            )
        self._raise_for_status(resp)
        pair = TokenPair(**resp.json())
        self._tokens.set_tokens(pair.access_token, pair.refresh_token, pair.expires_in)
        return pair

    async def refresh(self) -> TokenPair:
        """Refresh the current token pair using the stored refresh token."""
        rt = self._tokens.refresh_token
        if not rt:
            raise AuthenticationError("No refresh token available", 401)
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.post(
                f"{self.base_url}/v1/identity/refresh",
                json={"refresh_token": rt},
            )
        self._raise_for_status(resp)
        pair = TokenPair(**resp.json())
        self._tokens.set_tokens(pair.access_token, pair.refresh_token, pair.expires_in)
        return pair

    async def introspect(self, token: str) -> IntrospectResult:
        """Introspect a token to check its validity and claims."""
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.post(
                f"{self.base_url}/v1/identity/auth/introspect",
                json={"token": token},
            )
        self._raise_for_status(resp)
        return IntrospectResult(**resp.json())

    # -- Users --
    async def get_user(self, user_id: str) -> User:
        """Fetch a user by ID."""
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.get(
                f"{self.base_url}/v1/identity/users/{user_id}",
                headers=self._headers(),
            )
        self._raise_for_status(resp)
        return User(**resp.json())

    # -- Tenants --
    async def provision_tenant(
        self,
        name: str,
        slug: str,
        owner_email: str,
        owner_username: str,
        owner_password: str,
        plan: str = "starter",
    ) -> TenantProvisionResult:
        """Provision a new tenant with an owner account."""
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.post(
                f"{self.base_url}/v1/tenants/provision",
                json={
                    "name": name,
                    "slug": slug,
                    "owner_email": owner_email,
                    "owner_username": owner_username,
                    "owner_password": owner_password,
                    "plan": plan,
                },
                headers=self._headers(),
            )
        self._raise_for_status(resp)
        return TenantProvisionResult(**resp.json())

    # -- Health --
    async def health(self) -> HealthStatus:
        """Check the API health status."""
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            resp = await c.get(f"{self.base_url}/health")
        self._raise_for_status(resp)
        return HealthStatus(**resp.json())


class ZuultimateClient:
    """Sync client for the Zuultimate identity platform API."""

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._tokens = TokenManager()

    def _headers(self) -> dict:
        """Build authorization headers from API key or managed token."""
        if self._api_key:
            return {"Authorization": f"Bearer {self._api_key}"}
        token = self._tokens.access_token
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        """Raise a typed exception for non-2xx responses."""
        if resp.status_code == 401:
            raise AuthenticationError("Authentication failed", 401)
        if resp.status_code == 404:
            raise NotFoundError("Resource not found", 404)
        if resp.status_code == 422:
            raise ValidationError(resp.json().get("error", "Validation failed"), 422)
        if resp.status_code == 429:
            raise RateLimitError("Rate limited", 429)
        if resp.status_code >= 400:
            raise ZuultimateError(f"HTTP {resp.status_code}", resp.status_code)

    # -- Auth --
    def login(self, username: str, password: str) -> TokenPair:
        """Authenticate with username and password, returning a token pair."""
        resp = httpx.post(
            f"{self.base_url}/v1/identity/login",
            json={"username": username, "password": password},
            timeout=self._timeout,
        )
        self._raise_for_status(resp)
        pair = TokenPair(**resp.json())
        self._tokens.set_tokens(pair.access_token, pair.refresh_token, pair.expires_in)
        return pair

    # -- Health --
    def health(self) -> HealthStatus:
        """Check the API health status."""
        resp = httpx.get(f"{self.base_url}/health", timeout=self._timeout)
        self._raise_for_status(resp)
        return HealthStatus(**resp.json())
