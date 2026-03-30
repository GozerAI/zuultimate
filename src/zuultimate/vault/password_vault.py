"""Consumer password vault — user-scoped encrypted secrets manager."""

from sqlalchemy import select, delete as sa_delete

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.vault.crypto import decrypt_aes_gcm, derive_key, encrypt_aes_gcm
from zuultimate.vault.models import UserSecret

_DB_KEY = "credential"


class PasswordVaultService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self._key, _ = derive_key(settings.secret_key, salt=settings.password_vault_salt.encode())

    async def store_secret(
        self, user_id: str, name: str, value: str, category: str = "password", notes: str = ""
    ) -> dict:
        if not name:
            raise ValidationError("Secret name must not be empty")
        if not value:
            raise ValidationError("Secret value must not be empty")

        ct, nonce, tag = encrypt_aes_gcm(value.encode(), self._key)

        async with self.db.get_session(_DB_KEY) as session:
            # Check for duplicate name for this user
            result = await session.execute(
                select(UserSecret).where(
                    UserSecret.user_id == user_id,
                    UserSecret.name == name,
                )
            )
            existing = result.scalar_one_or_none()
            if existing is not None:
                # Update existing
                existing.ciphertext = ct
                existing.nonce = nonce
                existing.tag = tag
                existing.category = category
                existing.notes = notes
                secret_id = existing.id
            else:
                secret = UserSecret(
                    user_id=user_id,
                    name=name,
                    ciphertext=ct,
                    nonce=nonce,
                    tag=tag,
                    category=category,
                    notes=notes,
                )
                session.add(secret)
                await session.flush()
                secret_id = secret.id

        return {
            "id": secret_id,
            "name": name,
            "category": category,
            "notes": notes,
        }

    async def get_secret(self, user_id: str, secret_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(UserSecret).where(
                    UserSecret.id == secret_id,
                    UserSecret.user_id == user_id,
                )
            )
            secret = result.scalar_one_or_none()
            if secret is None:
                raise NotFoundError("Resource not found")

        plaintext = decrypt_aes_gcm(secret.ciphertext, self._key, secret.nonce, secret.tag)
        return {
            "id": secret.id,
            "name": secret.name,
            "value": plaintext.decode(),
            "category": secret.category,
            "notes": secret.notes,
        }

    async def list_secrets(self, user_id: str) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(UserSecret).where(UserSecret.user_id == user_id)
            )
            secrets = result.scalars().all()

        return [
            {
                "id": s.id,
                "name": s.name,
                "category": s.category,
                "notes": s.notes,
            }
            for s in secrets
        ]

    async def delete_secret(self, user_id: str, secret_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(UserSecret).where(
                    UserSecret.id == secret_id,
                    UserSecret.user_id == user_id,
                )
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Resource not found")

            await session.execute(
                sa_delete(UserSecret).where(UserSecret.id == secret_id)
            )

        return {"deleted": True, "id": secret_id}
