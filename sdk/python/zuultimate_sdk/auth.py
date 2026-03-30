"""Token acquisition and refresh helpers."""

import time


class TokenManager:
    """Manages token lifecycle — acquires, caches, and refreshes."""

    def __init__(self):
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at: float = 0.0

    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store a new token pair with computed expiry."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = time.time() + expires_in - 30  # refresh 30s before expiry

    @property
    def access_token(self) -> str | None:
        """Return the access token if still valid, otherwise None."""
        if self._access_token and time.time() < self._expires_at:
            return self._access_token
        return None

    @property
    def refresh_token(self) -> str | None:
        """Return the stored refresh token."""
        return self._refresh_token

    @property
    def needs_refresh(self) -> bool:
        """Return True if the token exists but has expired."""
        return self._access_token is not None and time.time() >= self._expires_at

    def clear(self) -> None:
        """Clear all stored tokens."""
        self._access_token = None
        self._refresh_token = None
        self._expires_at = 0.0
