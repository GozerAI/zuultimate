"""CRL (Certificate Revocation List) cache manager with periodic refresh."""

import logging
import time
from threading import Lock

_log = logging.getLogger("pop.crl_manager")


class CRLManager:
    """Manages a cached CRL with configurable refresh interval.

    In production, fetches CRL from the configured URL and parses revoked
    serial numbers. For now, maintains an in-memory set of revoked serials.
    """

    def __init__(self, crl_url: str = "", refresh_seconds: int = 900):
        self._crl_url = crl_url
        self._refresh_seconds = refresh_seconds
        self._revoked_serials: set[str] = set()
        self._last_refresh: float = 0
        self._lock = Lock()

    def is_revoked(self, serial: str) -> bool:
        """Check if a certificate serial is in the revocation list."""
        self._maybe_refresh()
        return serial in self._revoked_serials

    def add_revoked(self, serial: str) -> None:
        """Manually add a serial to the revocation list (for testing)."""
        with self._lock:
            self._revoked_serials.add(serial)

    def _maybe_refresh(self) -> None:
        """Refresh CRL if stale (older than refresh_seconds)."""
        now = time.time()
        if now - self._last_refresh < self._refresh_seconds:
            return

        with self._lock:
            # Double-check after acquiring lock
            if now - self._last_refresh < self._refresh_seconds:
                return
            self._refresh()
            self._last_refresh = now

    def _refresh(self) -> None:
        """Fetch and parse CRL from URL. Stub implementation."""
        if not self._crl_url:
            return

        try:
            # In production: fetch CRL via HTTP, parse with cryptography
            _log.info("CRL refresh from %s (stub)", self._crl_url)
        except Exception as exc:
            _log.warning("CRL refresh failed: %s", exc)
