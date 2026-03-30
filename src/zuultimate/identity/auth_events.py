"""Auth event emission -- structured audit events for authentication actions."""

import hashlib
import json
from datetime import datetime, timezone

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.identity.models import AuthEvent

_log = get_logger("zuultimate.auth_events")


def _hash_full(value: str) -> str:
    """Return the full SHA-256 hex digest of a string."""
    return hashlib.sha256(value.encode()).hexdigest()


def _hash_short(value: str, length: int = 16) -> str:
    """Return a truncated SHA-256 hex digest of a string."""
    return hashlib.sha256(value.encode()).hexdigest()[:length]


class AuthEventEmitter:
    """Emit structured auth events to the audit database.

    All identifiers are hashed at the emission point so no raw PII reaches
    storage.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def emit(
        self,
        *,
        event_type: str,
        ip: str,
        user_agent: str = "",
        username: str | None = None,
        tenant_id: str | None = None,
        metadata: dict | None = None,
    ) -> AuthEvent:
        """Write one auth event to the identity database and return the record."""
        event = AuthEvent(
            event_type=event_type,
            ip_hash=_hash_full(ip),
            user_agent_hash=_hash_short(user_agent),
            username_hash=_hash_short(username) if username else None,
            tenant_id_hash=_hash_full(tenant_id) if tenant_id else None,
            metadata_json=json.dumps(metadata or {}),
            created_at=datetime.now(timezone.utc),
        )
        async with self._db.get_session("identity") as session:
            session.add(event)
        _log.info("auth event emitted: %s", event_type)
        return event
