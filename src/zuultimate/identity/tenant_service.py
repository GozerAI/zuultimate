"""Tenant CRUD service."""

import hashlib
import secrets

from sqlalchemy import select

from zuultimate.common.config import PLAN_ENTITLEMENTS
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.common.security import hash_password
from zuultimate.identity.models import ApiKey, Credential, Tenant, User
from zuultimate.identity.schemas import ApiKeyCreateResponse, ApiKeyResponse, TenantProvisionResponse, TenantResponse

_DB_KEY = "identity"


class TenantService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_tenant(self, name: str, slug: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            existing = await session.execute(
                select(Tenant).where(Tenant.slug == slug)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Tenant slug already exists")

            tenant = Tenant(name=name, slug=slug)
            session.add(tenant)
            await session.flush()

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active,
            plan=tenant.plan, status=tenant.status,
        ).model_dump()

    async def list_tenants(self, active_only: bool = True) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            query = select(Tenant).order_by(Tenant.name)
            if active_only:
                query = query.where(Tenant.is_active == True)
            result = await session.execute(query)
            tenants = result.scalars().all()

        return [
            TenantResponse(
                id=t.id, name=t.name, slug=t.slug, is_active=t.is_active,
                plan=t.plan, status=t.status,
            ).model_dump()
            for t in tenants
        ]

    async def get_tenant(self, tenant_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant is None:
                raise NotFoundError("Tenant not found")

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active,
            plan=tenant.plan, status=tenant.status,
        ).model_dump()

    async def deactivate_tenant(self, tenant_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant is None:
                raise NotFoundError("Tenant not found")
            tenant.is_active = False
            await session.flush()

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active,
            plan=tenant.plan, status=tenant.status,
        ).model_dump()

    async def provision_tenant(
        self,
        name: str,
        slug: str,
        owner_email: str,
        owner_username: str,
        owner_password: str,
        plan: str = "starter",
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
    ) -> dict:
        """Atomic provisioning: create Tenant + owner User + API key."""
        async with self.db.get_session(_DB_KEY) as session:
            # Check slug uniqueness
            existing = await session.execute(
                select(Tenant).where(Tenant.slug == slug)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Tenant slug already exists")

            # Check email/username uniqueness
            existing = await session.execute(
                select(User).where((User.email == owner_email) | (User.username == owner_username))
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Owner email or username already exists")

            # Create tenant
            tenant = Tenant(
                name=name,
                slug=slug,
                plan=plan,
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
            )
            session.add(tenant)
            await session.flush()

            # Create owner user
            user = User(
                email=owner_email,
                username=owner_username,
                display_name=name,
                tenant_id=tenant.id,
                is_active=True,
                is_verified=True,
            )
            session.add(user)
            await session.flush()

            # Store password credential
            credential = Credential(
                user_id=user.id,
                credential_type="password",
                hashed_value=hash_password(owner_password),
            )
            session.add(credential)

            # Generate API key
            raw_key = f"gzr_{''.join(secrets.token_hex(24))}"
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = ApiKey(
                tenant_id=tenant.id,
                name="Default",
                key_prefix=raw_key[:8],
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()

        entitlements = PLAN_ENTITLEMENTS.get(plan, [])

        return TenantProvisionResponse(
            tenant_id=tenant.id,
            user_id=user.id,
            api_key=raw_key,
            plan=plan,
            entitlements=entitlements,
        ).model_dump()

    # ── API Key CRUD ──────────────────────────────────────────────────────────

    async def create_api_key(self, tenant_id: str, name: str) -> dict:
        """Create a new API key for a tenant. Returns the raw key (shown once)."""
        async with self.db.get_session(_DB_KEY) as session:
            # Verify tenant exists and is active
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active == True)
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Tenant not found or inactive")

            raw_key = f"gzr_{secrets.token_hex(24)}"
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = ApiKey(
                tenant_id=tenant_id,
                name=name,
                key_prefix=raw_key[:8],
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()

        return ApiKeyCreateResponse(
            id=api_key.id,
            tenant_id=api_key.tenant_id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            is_active=api_key.is_active,
            created_at=api_key.created_at.isoformat(),
            last_used_at=None,
            raw_key=raw_key,
        ).model_dump()

    async def list_api_keys(self, tenant_id: str) -> list[dict]:
        """List all API keys for a tenant (no raw keys returned)."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ApiKey)
                .where(ApiKey.tenant_id == tenant_id)
                .order_by(ApiKey.created_at)
            )
            keys = result.scalars().all()

        return [
            ApiKeyResponse(
                id=k.id,
                tenant_id=k.tenant_id,
                name=k.name,
                key_prefix=k.key_prefix,
                is_active=k.is_active,
                created_at=k.created_at.isoformat(),
                last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
            ).model_dump()
            for k in keys
        ]

    async def revoke_api_key(self, tenant_id: str, key_id: str) -> dict:
        """Deactivate an API key."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
            )
            api_key = result.scalar_one_or_none()
            if api_key is None:
                raise NotFoundError("API key not found")
            api_key.is_active = False
            await session.flush()

        return ApiKeyResponse(
            id=api_key.id,
            tenant_id=api_key.tenant_id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            is_active=api_key.is_active,
            created_at=api_key.created_at.isoformat(),
            last_used_at=api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        ).model_dump()

    async def delete_api_key(self, tenant_id: str, key_id: str) -> None:
        """Permanently delete an API key."""
        from sqlalchemy import delete as sa_delete

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                sa_delete(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
            )
            if result.rowcount == 0:
                raise NotFoundError("API key not found")

    async def rotate_api_key(self, tenant_id: str, key_id: str) -> dict:
        """Revoke old key and create a new one with the same name."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
            )
            old_key = result.scalar_one_or_none()
            if old_key is None:
                raise NotFoundError("API key not found")

            name = old_key.name
            old_key.is_active = False

            raw_key = f"gzr_{secrets.token_hex(24)}"
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            new_key = ApiKey(
                tenant_id=tenant_id,
                name=name,
                key_prefix=raw_key[:8],
                key_hash=key_hash,
            )
            session.add(new_key)
            await session.flush()

        return ApiKeyCreateResponse(
            id=new_key.id,
            tenant_id=new_key.tenant_id,
            name=new_key.name,
            key_prefix=new_key.key_prefix,
            is_active=new_key.is_active,
            created_at=new_key.created_at.isoformat(),
            last_used_at=None,
            raw_key=raw_key,
        ).model_dump()
