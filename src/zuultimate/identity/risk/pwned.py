"""Breached password detection via HIBP k-anonymity API."""

import hashlib

import httpx

from zuultimate.common.logging import get_logger

logger = get_logger(__name__)


class PwnedPasswordChecker:
    """Checks passwords against HIBP breach database using k-anonymity.

    No plaintext password leaves the service -- only the first 5 characters of
    the SHA-1 hash are sent to the HIBP range endpoint.
    """

    _RANGE_URL = "https://api.pwnedpasswords.com/range/"

    async def check(self, password: str) -> bool:
        """Return True if the password appears in known breaches."""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._RANGE_URL}{prefix}")
                resp.raise_for_status()
        except (httpx.HTTPError, httpx.RequestError) as exc:
            logger.warning("HIBP range API unreachable: %s", exc)
            return False

        for line in resp.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return True
        return False
