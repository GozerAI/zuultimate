"""Automated data subject request (DSAR) processing.

Orchestrates the lifecycle of GDPR/CCPA data subject access, deletion,
portability, and correction requests with SLA tracking.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class DSARType(str, Enum):
    ACCESS = "access"
    DELETION = "deletion"
    PORTABILITY = "portability"
    CORRECTION = "correction"
    RESTRICTION = "restriction"
    OBJECTION = "objection"


class DSARStatus(str, Enum):
    RECEIVED = "received"
    VALIDATED = "validated"
    PROCESSING = "processing"
    FULFILLED = "fulfilled"
    REJECTED = "rejected"


_VALID_TRANSITIONS: dict[DSARStatus, list[DSARStatus]] = {
    DSARStatus.RECEIVED: [DSARStatus.VALIDATED, DSARStatus.REJECTED],
    DSARStatus.VALIDATED: [DSARStatus.PROCESSING, DSARStatus.REJECTED],
    DSARStatus.PROCESSING: [DSARStatus.FULFILLED, DSARStatus.REJECTED],
    DSARStatus.FULFILLED: [],
    DSARStatus.REJECTED: [],
}


@dataclass
class DSAREntry:
    request_id: str
    tenant_id: str
    subject_id: str
    request_type: DSARType
    status: DSARStatus
    received_at: datetime
    due_at: datetime
    fulfilled_at: datetime | None = None
    rejected_at: datetime | None = None
    rejection_reason: str = ""
    evidence_trail: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_overdue(self) -> bool:
        if self.status in (DSARStatus.FULFILLED, DSARStatus.REJECTED):
            return False
        return datetime.now(timezone.utc) > self.due_at

    @property
    def days_remaining(self) -> float:
        delta = self.due_at - datetime.now(timezone.utc)
        return delta.total_seconds() / 86400

    @property
    def is_terminal(self) -> bool:
        return self.status in (DSARStatus.FULFILLED, DSARStatus.REJECTED)


class DSARProcessor:
    """Processes DSAR requests through their lifecycle.

    Usage::

        processor = DSARProcessor()
        entry = processor.submit("t1", "user-1", DSARType.ACCESS)
        processor.advance(entry.request_id, DSARStatus.VALIDATED)
    """

    def __init__(self, sla_days: int = 30) -> None:
        self._store: dict[str, DSAREntry] = {}
        self._counter = 0
        self.sla_days = sla_days

    def submit(
        self,
        tenant_id: str,
        subject_id: str,
        request_type: DSARType,
        metadata: dict[str, Any] | None = None,
    ) -> DSAREntry:
        self._counter += 1
        now = datetime.now(timezone.utc)
        entry = DSAREntry(
            request_id=f"dsar-{self._counter}",
            tenant_id=tenant_id, subject_id=subject_id,
            request_type=request_type, status=DSARStatus.RECEIVED,
            received_at=now, due_at=now + timedelta(days=self.sla_days),
            evidence_trail=[{"status": "received", "timestamp": now.isoformat(), "note": "Request received"}],
            metadata=metadata or {},
        )
        self._store[entry.request_id] = entry
        return entry

    def advance(self, request_id: str, new_status: DSARStatus, note: str = "") -> DSAREntry:
        entry = self._store.get(request_id)
        if entry is None:
            raise KeyError(f"DSAR request not found: {request_id}")

        valid_next = _VALID_TRANSITIONS.get(entry.status, [])
        if new_status not in valid_next:
            raise ValueError(
                f"Cannot transition from {entry.status.value} to {new_status.value}. "
                f"Valid transitions: {[s.value for s in valid_next]}"
            )

        entry.status = new_status
        now = datetime.now(timezone.utc)
        entry.evidence_trail.append({
            "status": new_status.value,
            "timestamp": now.isoformat(),
            "note": note or f"Status changed to {new_status.value}",
        })

        if new_status == DSARStatus.FULFILLED:
            entry.fulfilled_at = now
        elif new_status == DSARStatus.REJECTED:
            entry.rejected_at = now
            entry.rejection_reason = note

        return entry

    def get_request(self, request_id: str) -> DSAREntry | None:
        return self._store.get(request_id)

    def list_requests(
        self,
        tenant_id: str | None = None,
        status: DSARStatus | None = None,
    ) -> list[DSAREntry]:
        entries = list(self._store.values())
        if tenant_id:
            entries = [e for e in entries if e.tenant_id == tenant_id]
        if status:
            entries = [e for e in entries if e.status == status]
        return entries

    def get_overdue_requests(self) -> list[DSAREntry]:
        return [e for e in self._store.values() if e.is_overdue]

    def get_sla_summary(self, tenant_id: str | None = None) -> dict[str, Any]:
        entries = self.list_requests(tenant_id=tenant_id)
        if not entries:
            return {"total": 0, "fulfilled": 0, "overdue": 0, "pending": 0, "sla_compliance_rate": 1.0}

        fulfilled = [e for e in entries if e.status == DSARStatus.FULFILLED]
        overdue = [e for e in entries if e.is_overdue]
        pending = [e for e in entries if not e.is_terminal]

        fulfilled_on_time = sum(
            1 for e in fulfilled
            if e.fulfilled_at and e.fulfilled_at <= e.due_at
        )
        rate = fulfilled_on_time / len(fulfilled) if fulfilled else 1.0

        return {
            "total": len(entries),
            "fulfilled": len(fulfilled),
            "overdue": len(overdue),
            "pending": len(pending),
            "sla_compliance_rate": round(rate, 4),
        }
