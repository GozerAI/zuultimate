"""Automated key rotation scheduling.

Manages cryptographic key lifecycle: tracks key ages, schedules rotations,
enforces maximum key ages, and produces rotation plans.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class KeyType(str, Enum):
    RSA = "rsa"
    AES = "aes"
    HMAC = "hmac"
    JWT_SIGNING = "jwt_signing"
    VAULT_ENCRYPTION = "vault_encryption"
    API_KEY = "api_key"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    ROTATING = "rotating"
    RETIRED = "retired"
    COMPROMISED = "compromised"


@dataclass
class ManagedKey:
    key_id: str
    key_type: KeyType
    status: KeyStatus
    created_at: datetime
    last_rotated_at: datetime | None = None
    max_age_days: int = 90
    rotation_grace_days: int = 7
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def age_days(self) -> float:
        ref = self.last_rotated_at or self.created_at
        delta = datetime.now(timezone.utc) - ref
        return delta.total_seconds() / 86400

    @property
    def needs_rotation(self) -> bool:
        if self.status in (KeyStatus.RETIRED, KeyStatus.COMPROMISED):
            return False
        return self.age_days >= self.max_age_days

    @property
    def days_until_rotation(self) -> float:
        return max(0.0, self.max_age_days - self.age_days)

    @property
    def is_overdue(self) -> bool:
        return self.age_days > (self.max_age_days + self.rotation_grace_days)


@dataclass
class RotationPlan:
    key_id: str
    key_type: KeyType
    scheduled_at: datetime
    reason: str
    priority: int  # 1=urgent, 2=normal, 3=low


class KeyRotationScheduler:
    """Tracks keys and produces rotation schedules.

    Usage::

        scheduler = KeyRotationScheduler()
        scheduler.register_key(ManagedKey(
            key_id="jwt-sign-1", key_type=KeyType.JWT_SIGNING,
            status=KeyStatus.ACTIVE, created_at=datetime.now(timezone.utc),
            max_age_days=90,
        ))
        plans = scheduler.get_rotation_plan()
    """

    def __init__(self) -> None:
        self._keys: dict[str, ManagedKey] = {}

    def register_key(self, key: ManagedKey) -> None:
        self._keys[key.key_id] = key

    def unregister_key(self, key_id: str) -> bool:
        return self._keys.pop(key_id, None) is not None

    def get_key(self, key_id: str) -> ManagedKey | None:
        return self._keys.get(key_id)

    @property
    def all_keys(self) -> list[ManagedKey]:
        return list(self._keys.values())

    def mark_rotated(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key:
            key.last_rotated_at = datetime.now(timezone.utc)
            key.status = KeyStatus.ACTIVE

    def mark_compromised(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key:
            key.status = KeyStatus.COMPROMISED

    def retire_key(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key:
            key.status = KeyStatus.RETIRED

    def get_keys_needing_rotation(self) -> list[ManagedKey]:
        return [k for k in self._keys.values() if k.needs_rotation]

    def get_overdue_keys(self) -> list[ManagedKey]:
        return [k for k in self._keys.values() if k.is_overdue]

    def get_compromised_keys(self) -> list[ManagedKey]:
        return [k for k in self._keys.values() if k.status == KeyStatus.COMPROMISED]

    def get_rotation_plan(self) -> list[RotationPlan]:
        plans: list[RotationPlan] = []
        now = datetime.now(timezone.utc)

        for key in self._keys.values():
            if key.status == KeyStatus.COMPROMISED:
                plans.append(RotationPlan(
                    key_id=key.key_id, key_type=key.key_type,
                    scheduled_at=now, reason="Key compromised — immediate rotation required",
                    priority=1,
                ))
            elif key.is_overdue:
                plans.append(RotationPlan(
                    key_id=key.key_id, key_type=key.key_type,
                    scheduled_at=now, reason=f"Key overdue by {key.age_days - key.max_age_days:.1f} days",
                    priority=1,
                ))
            elif key.needs_rotation:
                scheduled = now + timedelta(days=1)
                plans.append(RotationPlan(
                    key_id=key.key_id, key_type=key.key_type,
                    scheduled_at=scheduled,
                    reason=f"Key age ({key.age_days:.1f}d) exceeds max ({key.max_age_days}d)",
                    priority=2,
                ))

        plans.sort(key=lambda p: p.priority)
        return plans

    def get_summary(self) -> dict[str, Any]:
        keys = self.all_keys
        return {
            "total_keys": len(keys),
            "active": sum(1 for k in keys if k.status == KeyStatus.ACTIVE),
            "pending_rotation": len(self.get_keys_needing_rotation()),
            "overdue": len(self.get_overdue_keys()),
            "compromised": len(self.get_compromised_keys()),
            "retired": sum(1 for k in keys if k.status == KeyStatus.RETIRED),
        }
