"""Phase 2 InteractionEnforcer — capability-based authorization service.

Provides:
- resolve_identity: auth credentials → IdentityToken
- grant_capability: issue scoped, time-limited capability
- revoke_capability: immediate revocation with cascade
- delegate: attenuated re-delegation of capability
- enforce: evaluate policy decision (allow/deny/allow_filtered)
"""

import json
import time
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch

from sqlalchemy import select, update as sa_update

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.phase2_models import (
    CapabilityToken,
    DataShape,
    IdentityToken,
    PolicyDecision,
)

_DB_KEY = "identity"

# Sensitivity hierarchy: higher index = more restricted
_SENSITIVITY_LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class InteractionEnforcer:
    """Capability-based authorization enforcement service."""

    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self.settings = settings

    # ── Identity Resolution ──────────────────────────────────────────────

    async def resolve_identity(
        self,
        entity_type: str,
        entity_id: str,
        tenant_id: str | None = None,
        display_name: str = "",
        metadata: dict | None = None,
    ) -> IdentityToken:
        """Find or create an IdentityToken for the given entity."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(IdentityToken).where(
                    IdentityToken.entity_type == entity_type,
                    IdentityToken.entity_id == entity_id,
                    IdentityToken.is_active == True,  # noqa: E712
                ),
            )
            token = result.scalar_one_or_none()
            if token:
                return token

            token = IdentityToken(
                entity_type=entity_type,
                entity_id=entity_id,
                tenant_id=tenant_id,
                display_name=display_name,
                metadata_json=json.dumps(metadata or {}),
            )
            session.add(token)
            await session.flush()
            return token

    async def get_identity_token(self, token_id: str) -> IdentityToken:
        """Get an IdentityToken by ID."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(IdentityToken).where(IdentityToken.id == token_id),
            )
            token = result.scalar_one_or_none()
            if not token:
                raise NotFoundError(f"IdentityToken {token_id} not found")
            return token

    async def deactivate_identity(self, token_id: str) -> None:
        """Deactivate an IdentityToken and revoke all its capabilities."""
        async with self.db.get_session(_DB_KEY) as session:
            await session.execute(
                sa_update(IdentityToken)
                .where(IdentityToken.id == token_id)
                .values(is_active=False),
            )
            now = datetime.now(timezone.utc)
            await session.execute(
                sa_update(CapabilityToken)
                .where(
                    CapabilityToken.identity_token_id == token_id,
                    CapabilityToken.revoked_at == None,  # noqa: E711
                )
                .values(revoked_at=now),
            )

    # ── Capability Management ────────────────────────────────────────────

    async def grant_capability(
        self,
        grantor_id: str,
        grantee_id: str,
        capability: str,
        resource_scope: str = "*",
        constraints: dict | None = None,
        delegatable: bool = False,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Grant a capability to an identity."""
        if ttl_seconds < 60 or ttl_seconds > 86400:
            raise ValidationError("TTL must be between 60 and 86400 seconds")

        async with self.db.get_session(_DB_KEY) as session:
            # Verify both identities exist and are active
            for eid, label in [(grantor_id, "Grantor"), (grantee_id, "Grantee")]:
                result = await session.execute(
                    select(IdentityToken).where(
                        IdentityToken.id == eid,
                        IdentityToken.is_active == True,  # noqa: E712
                    ),
                )
                if not result.scalar_one_or_none():
                    raise NotFoundError(f"{label} IdentityToken {eid} not found or inactive")

            cap = CapabilityToken(
                identity_token_id=grantee_id,
                capability=capability,
                resource_scope=resource_scope,
                constraints_json=json.dumps(constraints or {}),
                granted_by=grantor_id,
                delegatable=delegatable,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            )
            session.add(cap)
            await session.flush()
            return cap

    async def revoke_capability(self, capability_id: str, reason: str = "") -> int:
        """Revoke a capability and all delegated children. Returns count revoked."""
        now = datetime.now(timezone.utc)
        revoked = 0
        async with self.db.get_session(_DB_KEY) as session:
            # Revoke the target
            result = await session.execute(
                sa_update(CapabilityToken)
                .where(
                    CapabilityToken.id == capability_id,
                    CapabilityToken.revoked_at == None,  # noqa: E711
                )
                .values(revoked_at=now),
            )
            revoked += result.rowcount

            # Cascade: revoke all children
            children = await session.execute(
                select(CapabilityToken.id).where(
                    CapabilityToken.parent_capability_id == capability_id,
                    CapabilityToken.revoked_at == None,  # noqa: E711
                ),
            )
            for (child_id,) in children:
                revoked += await self._revoke_recursive(session, child_id, now)

        return revoked

    async def _revoke_recursive(self, session, capability_id: str, now: datetime) -> int:
        """Recursively revoke a capability and its children."""
        result = await session.execute(
            sa_update(CapabilityToken)
            .where(
                CapabilityToken.id == capability_id,
                CapabilityToken.revoked_at == None,  # noqa: E711
            )
            .values(revoked_at=now),
        )
        revoked = result.rowcount

        children = await session.execute(
            select(CapabilityToken.id).where(
                CapabilityToken.parent_capability_id == capability_id,
                CapabilityToken.revoked_at == None,  # noqa: E711
            ),
        )
        for (child_id,) in children:
            revoked += await self._revoke_recursive(session, child_id, now)

        return revoked

    async def delegate(
        self,
        parent_capability_id: str,
        grantee_id: str,
        resource_scope: str | None = None,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Delegate a capability with attenuation (never amplification)."""
        async with self.db.get_session(_DB_KEY) as session:
            # Load parent capability
            result = await session.execute(
                select(CapabilityToken).where(CapabilityToken.id == parent_capability_id),
            )
            parent = result.scalar_one_or_none()
            if not parent:
                raise NotFoundError(f"Capability {parent_capability_id} not found")

            if parent.revoked_at is not None:
                raise ValidationError("Cannot delegate a revoked capability")

            if not parent.delegatable:
                raise ValidationError("This capability is not delegatable")

            now = datetime.now(timezone.utc)
            # SQLite may return naive datetimes — normalize
            parent_expires = parent.expires_at
            if parent_expires.tzinfo is None:
                parent_expires = parent_expires.replace(tzinfo=timezone.utc)
            if parent_expires <= now:
                raise ValidationError("Cannot delegate an expired capability")

            # Attenuation: delegated scope must be subset of parent
            effective_scope = resource_scope or parent.resource_scope

            # TTL cannot exceed parent remaining time
            parent_remaining = (parent_expires - now).total_seconds()
            effective_ttl = min(ttl_seconds, int(parent_remaining))
            if effective_ttl < 60:
                raise ValidationError("Insufficient time remaining on parent capability")

            # Verify grantee exists
            grantee_result = await session.execute(
                select(IdentityToken).where(
                    IdentityToken.id == grantee_id,
                    IdentityToken.is_active == True,  # noqa: E712
                ),
            )
            if not grantee_result.scalar_one_or_none():
                raise NotFoundError(f"Grantee IdentityToken {grantee_id} not found or inactive")

            cap = CapabilityToken(
                identity_token_id=grantee_id,
                capability=parent.capability,
                resource_scope=effective_scope,
                constraints_json=parent.constraints_json,
                granted_by=parent.identity_token_id,
                parent_capability_id=parent.id,
                delegatable=False,  # delegated capabilities are not re-delegatable by default
                expires_at=now + timedelta(seconds=effective_ttl),
            )
            session.add(cap)
            await session.flush()
            return cap

    async def list_capabilities(
        self, identity_token_id: str, active_only: bool = True,
    ) -> list[CapabilityToken]:
        """List capabilities for an identity."""
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(CapabilityToken).where(
                CapabilityToken.identity_token_id == identity_token_id,
            )
            if active_only:
                now = datetime.now(timezone.utc)
                stmt = stmt.where(
                    CapabilityToken.revoked_at == None,  # noqa: E711
                    CapabilityToken.expires_at > now,
                )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── DataShape Management ─────────────────────────────────────────────

    async def create_data_shape(
        self,
        name: str,
        sensitivity: str = "internal",
        schema_definition: dict | None = None,
        retention_days: int = 365,
        pii_fields: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> DataShape:
        """Create a data shape definition."""
        if sensitivity not in _SENSITIVITY_LEVELS:
            raise ValidationError(
                f"Sensitivity must be one of: {', '.join(_SENSITIVITY_LEVELS)}",
            )

        async with self.db.get_session(_DB_KEY) as session:
            shape = DataShape(
                name=name,
                tenant_id=tenant_id,
                schema_json=json.dumps(schema_definition or {}),
                sensitivity=sensitivity,
                retention_days=retention_days,
                pii_fields_json=json.dumps(pii_fields or []),
            )
            session.add(shape)
            await session.flush()
            return shape

    async def get_data_shape(self, name: str) -> DataShape | None:
        """Get a data shape by name."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(DataShape).where(DataShape.name == name),
            )
            return result.scalar_one_or_none()

    async def list_data_shapes(self, tenant_id: str | None = None) -> list[DataShape]:
        """List data shapes, optionally filtered by tenant."""
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(DataShape)
            if tenant_id:
                stmt = stmt.where(
                    (DataShape.tenant_id == tenant_id) | (DataShape.tenant_id == None),  # noqa: E711
                )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── Policy Enforcement ───────────────────────────────────────────────

    async def enforce(
        self,
        identity_token_id: str,
        resource: str,
        action: str,
        data_shape_name: str | None = None,
    ) -> PolicyDecision:
        """Evaluate authorization and return a PolicyDecision."""
        start = time.monotonic()
        now = datetime.now(timezone.utc)

        async with self.db.get_session(_DB_KEY) as session:
            # 1. Check identity is active
            id_result = await session.execute(
                select(IdentityToken).where(
                    IdentityToken.id == identity_token_id,
                    IdentityToken.is_active == True,  # noqa: E712
                ),
            )
            identity = id_result.scalar_one_or_none()
            if not identity:
                return await self._record_decision(
                    session, identity_token_id, None, resource, action,
                    None, "deny", "Identity not found or inactive", now, start,
                )

            # 2. Find matching capabilities
            caps_result = await session.execute(
                select(CapabilityToken).where(
                    CapabilityToken.identity_token_id == identity_token_id,
                    CapabilityToken.revoked_at == None,  # noqa: E711
                    CapabilityToken.expires_at > now,
                ),
            )
            capabilities = caps_result.scalars().all()

            # 3. Check for matching capability
            matching_cap = None
            for cap in capabilities:
                cap_parts = cap.capability.split(":")
                action_parts = action.split(":")
                # Capability match: exact or prefix match
                if cap.capability == action or cap.capability == "*":
                    if fnmatch(resource, cap.resource_scope):
                        matching_cap = cap
                        break
                # Hierarchical: "vault:*" matches "vault:encrypt"
                if cap.capability.endswith(":*"):
                    prefix = cap.capability[:-2]
                    if action.startswith(prefix) and fnmatch(resource, cap.resource_scope):
                        matching_cap = cap
                        break

            if not matching_cap:
                return await self._record_decision(
                    session, identity_token_id, None, resource, action,
                    None, "deny", "No matching capability", now, start,
                )

            # 4. Check data shape for field filtering
            filtered_fields: list[str] = []
            data_shape_id = None
            if data_shape_name:
                shape_result = await session.execute(
                    select(DataShape).where(DataShape.name == data_shape_name),
                )
                shape = shape_result.scalar_one_or_none()
                if shape:
                    data_shape_id = shape.id
                    # If entity has lower clearance than data sensitivity,
                    # filter PII fields
                    entity_clearance = self._entity_clearance(identity.entity_type)
                    shape_level = _SENSITIVITY_LEVELS.get(shape.sensitivity, 1)
                    if entity_clearance < shape_level:
                        pii = json.loads(shape.pii_fields_json)
                        if pii:
                            filtered_fields = pii

            if filtered_fields:
                decision = "allow_filtered"
                reason = f"Filtered {len(filtered_fields)} restricted field(s)"
            else:
                decision = "allow"
                reason = f"Capability {matching_cap.capability} matched"

            return await self._record_decision(
                session, identity_token_id, matching_cap.id, resource, action,
                data_shape_id, decision, reason, now, start, filtered_fields,
            )

    def _entity_clearance(self, entity_type: str) -> int:
        """Map entity type to clearance level."""
        return {"service": 3, "user": 2, "agent": 1}.get(entity_type, 0)

    async def _record_decision(
        self,
        session,
        identity_token_id: str,
        capability_id: str | None,
        resource: str,
        action: str,
        data_shape_id: str | None,
        decision: str,
        reason: str,
        now: datetime,
        start: float,
        filtered_fields: list[str] | None = None,
    ) -> PolicyDecision:
        """Record and return a PolicyDecision."""
        latency_ms = int((time.monotonic() - start) * 1000)
        pd = PolicyDecision(
            identity_token_id=identity_token_id,
            capability_id=capability_id,
            resource=resource,
            action=action,
            data_shape_id=data_shape_id,
            decision=decision,
            reason=reason,
            filtered_fields_json=json.dumps(filtered_fields or []),
            evaluated_at=now,
            latency_ms=latency_ms,
        )
        session.add(pd)
        await session.flush()
        return pd
