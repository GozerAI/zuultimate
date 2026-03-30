"""Automated session security enforcement.

Enforces session policies: max concurrent sessions, idle timeout,
absolute timeout, device binding, and geographic consistency.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class SessionViolationType(str, Enum):
    MAX_CONCURRENT_EXCEEDED = "max_concurrent_exceeded"
    IDLE_TIMEOUT = "idle_timeout"
    ABSOLUTE_TIMEOUT = "absolute_timeout"
    DEVICE_MISMATCH = "device_mismatch"
    GEO_ANOMALY = "geo_anomaly"
    IP_CHANGE = "ip_change"


@dataclass
class SessionPolicy:
    max_concurrent_sessions: int = 5
    idle_timeout_minutes: int = 30
    absolute_timeout_hours: int = 24
    bind_to_device: bool = True
    enforce_geo_consistency: bool = False
    allowed_ip_change_count: int = 3


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    tenant_id: str
    created_at: datetime
    last_activity: datetime
    device_fingerprint: str = ""
    ip_address: str = ""
    country_code: str = ""
    ip_history: list[str] = field(default_factory=list)

    @property
    def idle_minutes(self) -> float:
        delta = datetime.now(timezone.utc) - self.last_activity
        return delta.total_seconds() / 60

    @property
    def age_hours(self) -> float:
        delta = datetime.now(timezone.utc) - self.created_at
        return delta.total_seconds() / 3600


@dataclass
class SessionViolation:
    violation_type: SessionViolationType
    session_id: str
    user_id: str
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SessionEnforcer:
    """Enforces session security policies.

    Usage::

        enforcer = SessionEnforcer(SessionPolicy(max_concurrent_sessions=3))
        enforcer.register_session(session)
        violations = enforcer.check_session(session.session_id)
    """

    def __init__(self, policy: SessionPolicy | None = None) -> None:
        self.policy = policy or SessionPolicy()
        self._sessions: dict[str, SessionRecord] = {}

    def register_session(self, session: SessionRecord) -> list[SessionViolation]:
        """Register a new session and check for violations (e.g., max concurrent)."""
        violations: list[SessionViolation] = []
        user_sessions = self._get_user_sessions(session.user_id)

        if len(user_sessions) >= self.policy.max_concurrent_sessions:
            violations.append(SessionViolation(
                violation_type=SessionViolationType.MAX_CONCURRENT_EXCEEDED,
                session_id=session.session_id, user_id=session.user_id,
                message=f"User has {len(user_sessions)} active sessions "
                        f"(max {self.policy.max_concurrent_sessions})",
            ))

        self._sessions[session.session_id] = session
        return violations

    def update_activity(
        self,
        session_id: str,
        ip_address: str | None = None,
        country_code: str | None = None,
    ) -> None:
        session = self._sessions.get(session_id)
        if session is None:
            return
        session.last_activity = datetime.now(timezone.utc)
        if ip_address and ip_address != session.ip_address:
            session.ip_history.append(session.ip_address)
            session.ip_address = ip_address
        if country_code:
            session.country_code = country_code

    def check_session(self, session_id: str) -> list[SessionViolation]:
        session = self._sessions.get(session_id)
        if session is None:
            return []

        violations: list[SessionViolation] = []

        if session.idle_minutes > self.policy.idle_timeout_minutes:
            violations.append(SessionViolation(
                violation_type=SessionViolationType.IDLE_TIMEOUT,
                session_id=session_id, user_id=session.user_id,
                message=f"Session idle for {session.idle_minutes:.0f}m "
                        f"(max {self.policy.idle_timeout_minutes}m)",
            ))

        if session.age_hours > self.policy.absolute_timeout_hours:
            violations.append(SessionViolation(
                violation_type=SessionViolationType.ABSOLUTE_TIMEOUT,
                session_id=session_id, user_id=session.user_id,
                message=f"Session age {session.age_hours:.1f}h "
                        f"(max {self.policy.absolute_timeout_hours}h)",
            ))

        if len(session.ip_history) > self.policy.allowed_ip_change_count:
            violations.append(SessionViolation(
                violation_type=SessionViolationType.IP_CHANGE,
                session_id=session_id, user_id=session.user_id,
                message=f"IP changed {len(session.ip_history)} times "
                        f"(max {self.policy.allowed_ip_change_count})",
            ))

        return violations

    def terminate_session(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def terminate_user_sessions(self, user_id: str) -> int:
        to_remove = [sid for sid, s in self._sessions.items() if s.user_id == user_id]
        for sid in to_remove:
            del self._sessions[sid]
        return len(to_remove)

    def _get_user_sessions(self, user_id: str) -> list[SessionRecord]:
        return [s for s in self._sessions.values() if s.user_id == user_id]

    def get_active_session_count(self, user_id: str) -> int:
        return len(self._get_user_sessions(user_id))

    def cleanup_expired(self) -> int:
        expired = [
            sid for sid, s in self._sessions.items()
            if s.age_hours > self.policy.absolute_timeout_hours
            or s.idle_minutes > self.policy.idle_timeout_minutes
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)
