"""Session store with lazy deserialization.

Item #51: Session store with lazy deserialization.

Wraps session data in a lazy proxy so JSON parsing only happens when a field
is actually accessed.  This avoids the cost of deserializing large session
payloads for requests that only need to check existence or a single field.
"""

from __future__ import annotations

import json
from typing import Any

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.session_store")


class LazySession:
    """Proxy that defers JSON deserialization until attribute access.

    The raw JSON string is stored on construction.  ``__getitem__`` and
    ``get()`` trigger parsing on first access.
    """

    __slots__ = ("_raw", "_parsed", "_deserialized")

    def __init__(self, raw: str) -> None:
        self._raw = raw
        self._parsed: dict[str, Any] | None = None
        self._deserialized = False

    def _ensure_parsed(self) -> dict[str, Any]:
        if not self._deserialized:
            self._parsed = json.loads(self._raw)
            self._deserialized = True
        return self._parsed  # type: ignore[return-value]

    def __getitem__(self, key: str) -> Any:
        return self._ensure_parsed()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._ensure_parsed().get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self._ensure_parsed()

    def to_dict(self) -> dict[str, Any]:
        return self._ensure_parsed()

    @property
    def is_deserialized(self) -> bool:
        return self._deserialized

    @property
    def raw(self) -> str:
        return self._raw

    def __repr__(self) -> str:
        if self._deserialized:
            return f"LazySession({self._parsed!r})"
        return f"LazySession(raw={len(self._raw)} bytes)"


class LazySessionStore:
    """In-process session store returning ``LazySession`` wrappers.

    Used as a local L1 cache in front of the Redis-backed session store.
    Only deserializes session JSON when fields are actually read.
    """

    def __init__(self, *, max_size: int = 4096, ttl: float = 30.0):
        from zuultimate.performance.caching import TTLCache

        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)

    def get(self, jti: str) -> LazySession | None:
        """Return a LazySession if cached, else None."""
        raw = self._cache.get(f"sess:{jti}")
        if raw is None:
            return None
        return LazySession(raw)

    def put(self, jti: str, raw_json: str) -> None:
        """Store raw JSON string without parsing it."""
        self._cache.put(f"sess:{jti}", raw_json)

    def invalidate(self, jti: str) -> bool:
        return self._cache.invalidate(f"sess:{jti}")

    @property
    def stats(self) -> dict[str, int]:
        return self._cache.stats
