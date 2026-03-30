"""Offline session management.

Manages user sessions when connectivity to the primary session store is
unavailable. Sessions are tracked locally and synced back when connectivity
is restored.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class OfflineSessionState(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    SYNCED = "synced"
    PENDING_SYNC = "pending_sync"
    INVALIDATED = "invalidated"


@dataclass
class OfflineSession:
    """A locally managed session for offline operation."""
    session_id: str
    user_id: str
    tenant_id: str
    state: OfflineSessionState
    created_at: float
    last_activity: float
    expires_at: float
    ip_address: str = ""
    user_agent: str = ""
    device_fingerprint: str = ""
    access_log: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_activity

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def needs_sync(self) -> bool:
        return self.state == OfflineSessionState.PENDING_SYNC


@dataclass
class SessionSyncResult:
    session_id: str
    synced: bool
    message: str = ""


class OfflineSessionManager:
    """Manages sessions during offline operation.

    Usage::

        manager = OfflineSessionManager(idle_timeout_minutes=30)
        session = manager.create_session("user-1", "tenant-1")
        manager.touch(session.session_id)
        expired = manager.cleanup_expired()
    """

    def __init__(
        self,
        idle_timeout_minutes: int = 30,
        absolute_timeout_hours: int = 24,
        max_sessions_per_user: int = 5,
        max_total_sessions: int = 10000,
    ) -> None:
        self.idle_timeout_minutes = idle_timeout_minutes
        self.absolute_timeout_hours = absolute_timeout_hours
        self.max_sessions_per_user = max_sessions_per_user
        self.max_total_sessions = max_total_sessions
        self._sessions: dict[str, OfflineSession] = {}
        self._counter = 0

    def create_session(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str = "",
        user_agent: str = "",
        device_fingerprint: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> OfflineSession:
        """Create a new offline session."""
        # Enforce per-user limit
        user_sessions = self._get_user_sessions(user_id)
        if len(user_sessions) >= self.max_sessions_per_user:
            # Evict oldest
            oldest = min(user_sessions, key=lambda s: s.last_activity)
            self.invalidate(oldest.session_id)

        # Enforce total limit
        if len(self._sessions) >= self.max_total_sessions:
            oldest_key = min(self._sessions, key=lambda k: self._sessions[k].last_activity)
            del self._sessions[oldest_key]

        self._counter += 1
        now = time.time()
        session = OfflineSession(
            session_id=f"offline-{self._counter}-{hashlib.sha256(f'{user_id}{now}'.encode()).hexdigest()[:8]}",
            user_id=user_id, tenant_id=tenant_id,
            state=OfflineSessionState.ACTIVE,
            created_at=now, last_activity=now,
            expires_at=now + self.absolute_timeout_hours * 3600,
            ip_address=ip_address, user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            access_log=[{"action": "created", "timestamp": now}],
            metadata=metadata or {},
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> OfflineSession | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        # Auto-expire
        if session.is_expired or session.idle_seconds > self.idle_timeout_minutes * 60:
            session.state = OfflineSessionState.EXPIRED
        return session

    def touch(self, session_id: str) -> bool:
        """Update last activity timestamp. Returns False if session not found or expired."""
        session = self.get_session(session_id)
        if session is None or session.state != OfflineSessionState.ACTIVE:
            return False
        session.last_activity = time.time()
        session.access_log.append({"action": "touch", "timestamp": time.time()})
        return True

    def invalidate(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = OfflineSessionState.INVALIDATED
        return True

    def invalidate_user_sessions(self, user_id: str) -> int:
        count = 0
        for session in self._get_user_sessions(user_id):
            if session.state == OfflineSessionState.ACTIVE:
                session.state = OfflineSessionState.INVALIDATED
                count += 1
        return count

    def mark_for_sync(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = OfflineSessionState.PENDING_SYNC
        return True

    def mark_synced(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = OfflineSessionState.SYNCED
        return True

    def get_pending_sync(self) -> list[OfflineSession]:
        return [s for s in self._sessions.values() if s.needs_sync]

    def cleanup_expired(self) -> int:
        expired = []
        for sid, session in self._sessions.items():
            if session.is_expired or session.idle_seconds > self.idle_timeout_minutes * 60:
                expired.append(sid)
        for sid in expired:
            self._sessions[sid].state = OfflineSessionState.EXPIRED
        return len(expired)

    def purge_inactive(self) -> int:
        """Remove sessions that are expired, synced, or invalidated."""
        removable = [
            sid for sid, s in self._sessions.items()
            if s.state in (OfflineSessionState.EXPIRED, OfflineSessionState.SYNCED,
                          OfflineSessionState.INVALIDATED)
        ]
        for sid in removable:
            del self._sessions[sid]
        return len(removable)

    def _get_user_sessions(self, user_id: str) -> list[OfflineSession]:
        return [s for s in self._sessions.values() if s.user_id == user_id]

    def get_active_count(self, user_id: str | None = None) -> int:
        sessions = self._sessions.values()
        if user_id:
            sessions = [s for s in sessions if s.user_id == user_id]
        return sum(1 for s in sessions if s.state == OfflineSessionState.ACTIVE)

    def get_summary(self) -> dict[str, Any]:
        sessions = list(self._sessions.values())
        return {
            "total_sessions": len(sessions),
            "active": sum(1 for s in sessions if s.state == OfflineSessionState.ACTIVE),
            "expired": sum(1 for s in sessions if s.state == OfflineSessionState.EXPIRED),
            "pending_sync": sum(1 for s in sessions if s.state == OfflineSessionState.PENDING_SYNC),
            "synced": sum(1 for s in sessions if s.state == OfflineSessionState.SYNCED),
            "invalidated": sum(1 for s in sessions if s.state == OfflineSessionState.INVALIDATED),
            "idle_timeout_minutes": self.idle_timeout_minutes,
            "absolute_timeout_hours": self.absolute_timeout_hours,
        }
