"""Webhook event bus — publish events to registered webhook endpoints."""

import asyncio
import hashlib
import hmac
import json
import socket
from datetime import datetime, timezone
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from sqlalchemy import Boolean, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.common.models import Base, TimestampMixin, generate_uuid

_log = get_logger("zuultimate.webhooks")
_DB_KEY = "audit"
_MAX_RETRIES = 3
_RETRY_DELAYS = [1, 5, 30]  # exponential backoff seconds


class WebhookConfig(Base, TimestampMixin):
    __tablename__ = "webhook_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    events_filter: Mapped[str] = mapped_column(String(500), default="*")
    secret: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")


class WebhookDelivery(Base, TimestampMixin):
    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    webhook_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    response_code: Mapped[int | None] = mapped_column(nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)


_BLOCKED_NETWORKS = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ip_network("::1/128"),
    ip_network("fc00::/7"),  # IPv6 private
]


def validate_webhook_url(url: str) -> None:
    """Validate that a webhook URL does not target internal/private networks (SSRF protection).

    Raises ValueError if the URL resolves to a blocked network.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https, got: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has no hostname")

    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, addr in resolved:
            addr_obj = ip_address(addr[0])
            for net in _BLOCKED_NETWORKS:
                if addr_obj in net:
                    raise ValueError(
                        f"Webhook URL resolves to private/internal address ({addr[0]})"
                    )
    except socket.gaierror:
        raise ValueError(f"Cannot resolve webhook hostname: {hostname}")


def _sign_payload(payload: str, secret: str) -> str:
    """HMAC-SHA256 signature for webhook payload verification."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _matches_filter(event_type: str, filter_pattern: str) -> bool:
    """Check if event_type matches a comma-separated list of glob patterns."""
    patterns = [p.strip() for p in filter_pattern.split(",")]
    return any(fnmatch(event_type, p) for p in patterns)


class WebhookService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_webhook(
        self, url: str, events_filter: str = "*", secret: str = "", description: str = ""
    ) -> dict:
        validate_webhook_url(url)
        async with self.db.get_session(_DB_KEY) as session:
            webhook = WebhookConfig(
                url=url,
                events_filter=events_filter,
                secret=secret,
                description=description,
            )
            session.add(webhook)
            await session.flush()

        return {
            "id": webhook.id,
            "url": webhook.url,
            "events_filter": webhook.events_filter,
            "is_active": webhook.is_active,
            "description": webhook.description,
        }

    async def list_webhooks(self) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebhookConfig).where(WebhookConfig.is_active == True)
            )
            webhooks = result.scalars().all()

        return [
            {
                "id": w.id,
                "url": w.url,
                "events_filter": w.events_filter,
                "is_active": w.is_active,
                "description": w.description,
            }
            for w in webhooks
        ]

    async def delete_webhook(self, webhook_id: str) -> None:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebhookConfig).where(WebhookConfig.id == webhook_id)
            )
            webhook = result.scalar_one_or_none()
            if webhook is not None:
                webhook.is_active = False

    async def get_matching_webhooks(self, event_type: str) -> list[WebhookConfig]:
        """Return active webhooks whose events_filter matches the event type."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebhookConfig).where(WebhookConfig.is_active == True)
            )
            all_hooks = result.scalars().all()

        return [w for w in all_hooks if _matches_filter(event_type, w.events_filter)]

    async def publish(self, event_type: str, payload: dict, fire: bool = False) -> list[dict]:
        """Publish an event to all matching webhooks. Returns delivery records.

        If ``fire=True``, schedule async HTTP delivery with retries in the
        background. Otherwise, just record delivery intent for later processing.
        """
        matching = await self.get_matching_webhooks(event_type)
        deliveries = []

        event_payload = json.dumps({
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        })

        async with self.db.get_session(_DB_KEY) as session:
            for webhook in matching:
                delivery = WebhookDelivery(
                    webhook_id=webhook.id,
                    event_type=event_type,
                    status="queued",
                    payload=event_payload,
                )
                session.add(delivery)
                await session.flush()

                record = {
                    "delivery_id": delivery.id,
                    "webhook_id": webhook.id,
                    "url": webhook.url,
                    "event_type": event_type,
                    "status": "queued",
                }
                if webhook.secret:
                    record["signature"] = _sign_payload(event_payload, webhook.secret)

                deliveries.append(record)

        if deliveries:
            _log.info(
                "Published %s to %d webhooks", event_type, len(deliveries)
            )

        if fire and deliveries:
            for d in deliveries:
                asyncio.create_task(
                    self._deliver_with_retries(
                        d["delivery_id"], d["url"], event_payload,
                        d.get("signature"),
                    )
                )

        return deliveries

    async def _deliver_with_retries(
        self,
        delivery_id: str,
        url: str,
        payload: str,
        signature: str | None = None,
    ) -> None:
        """POST the payload to the webhook URL with exponential backoff retries."""
        import httpx

        headers = {"Content-Type": "application/json"}
        if signature:
            headers["X-Webhook-Signature"] = signature

        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(url, content=payload, headers=headers)

                await self._update_delivery(
                    delivery_id,
                    status="delivered" if resp.status_code < 400 else "failed",
                    response_code=resp.status_code,
                    attempt=attempt + 1,
                )

                if resp.status_code < 400:
                    _log.info("Webhook %s delivered (attempt %d)", delivery_id, attempt + 1)
                    return

                _log.warning(
                    "Webhook %s returned %d (attempt %d/%d)",
                    delivery_id, resp.status_code, attempt + 1, _MAX_RETRIES,
                )

            except Exception as exc:
                _log.warning(
                    "Webhook %s failed (attempt %d/%d): %s",
                    delivery_id, attempt + 1, _MAX_RETRIES, exc,
                )
                await self._update_delivery(
                    delivery_id,
                    status="retrying" if attempt < _MAX_RETRIES - 1 else "failed",
                    attempt=attempt + 1,
                    error=str(exc),
                )

            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_RETRY_DELAYS[attempt])

    async def _update_delivery(
        self,
        delivery_id: str,
        status: str,
        response_code: int | None = None,
        attempt: int = 0,
        error: str | None = None,
    ) -> None:
        """Update delivery record in the database."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
            )
            delivery = result.scalar_one_or_none()
            if delivery:
                delivery.status = status
                delivery.attempt_count = attempt
                if response_code is not None:
                    delivery.response_code = response_code
                if error is not None:
                    delivery.last_error = error

    async def get_delivery(self, delivery_id: str) -> dict | None:
        """Fetch a delivery record by ID."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
            )
            d = result.scalar_one_or_none()
            if d is None:
                return None
        return {
            "id": d.id,
            "webhook_id": d.webhook_id,
            "event_type": d.event_type,
            "status": d.status,
            "response_code": d.response_code,
            "attempt_count": d.attempt_count,
            "last_error": d.last_error,
        }
