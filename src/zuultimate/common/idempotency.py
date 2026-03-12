"""Idempotency key support for POST/PUT endpoints."""

import json

from sqlalchemy import String, Text, Integer, select
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.database import DatabaseManager
from zuultimate.common.models import Base, TimestampMixin, generate_uuid

_DB_KEY = "audit"


class IdempotencyRecord(Base, TimestampMixin):
    __tablename__ = "idempotency_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    response_status: Mapped[int] = mapped_column(Integer, nullable=False)
    response_body: Mapped[str] = mapped_column(Text, nullable=False)


class IdempotencyService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def get_cached(self, key: str) -> dict | None:
        """Look up a previously stored response for this idempotency key."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.idempotency_key == key
                )
            )
            record = result.scalar_one_or_none()
            if record is None:
                return None

        return {
            "status_code": record.response_status,
            "body": json.loads(record.response_body),
        }

    async def store(self, key: str, endpoint: str, status_code: int, body: dict) -> None:
        """Store a response for future idempotency lookups."""
        async with self.db.get_session(_DB_KEY) as session:
            record = IdempotencyRecord(
                idempotency_key=key,
                endpoint=endpoint,
                response_status=status_code,
                response_body=json.dumps(body),
            )
            session.add(record)
