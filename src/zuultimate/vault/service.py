"""Vault service -- encrypt/decrypt blobs, tokenize/detokenize values."""

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.vault.crypto import decrypt_aes_gcm, derive_key, encrypt_aes_gcm
from zuultimate.vault.models import EncryptedBlob, VaultToken

_DB_KEY = "credential"


def _derive_vault_key(settings: ZuulSettings) -> bytes:
    """Derive AES key using a deployment-unique salt from secret_key."""
    salt = hashlib.sha256(
        settings.vault_salt.encode() + b"-" + settings.secret_key.encode()
    ).digest()[:16]
    key, _ = derive_key(settings.secret_key, salt=salt)
    return key


class VaultService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self._key = _derive_vault_key(settings)

    async def encrypt(self, plaintext: str, label: str = "", owner_id: str = "") -> dict:
        if not plaintext:
            raise ValidationError("Plaintext must not be empty")
        ciphertext, nonce, tag = encrypt_aes_gcm(plaintext.encode(), self._key)
        async with self.db.get_session(_DB_KEY) as session:
            blob = EncryptedBlob(
                owner_id=owner_id,
                label=label,
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
            )
            session.add(blob)
            await session.flush()
        return {"blob_id": blob.id, "label": label}

    async def decrypt(self, blob_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(EncryptedBlob).where(EncryptedBlob.id == blob_id)
            )
            blob = result.scalar_one_or_none()
            if blob is None:
                raise NotFoundError("Resource not found")
            plaintext = decrypt_aes_gcm(blob.ciphertext, self._key, blob.nonce, blob.tag)
        return {"plaintext": plaintext.decode()}

    async def tokenize(self, value: str) -> dict:
        if not value:
            raise ValidationError("Value must not be empty")
        value_hash = hashlib.sha256(value.encode()).hexdigest()

        async with self.db.get_session(_DB_KEY) as session:
            # Idempotent: return existing token if same value already tokenized
            result = await session.execute(
                select(VaultToken).where(VaultToken.original_hash == value_hash)
            )
            existing = result.scalar_one_or_none()
            if existing is not None:
                return {"token": existing.token_value}

            # Encrypt original value for reversible detokenization
            ct, nonce, tag = encrypt_aes_gcm(value.encode(), self._key)
            token_value = f"tok_{value_hash[:32]}"
            token = VaultToken(
                original_hash=value_hash,
                token_value=token_value,
                encrypted_value=ct,
                encrypted_nonce=nonce,
                encrypted_tag=tag,
            )
            session.add(token)
            await session.flush()
        return {"token": token_value}

    async def rotate_blob(self, blob_id: str) -> dict:
        """Re-encrypt a blob with a fresh nonce (same key). Returns updated blob info."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(EncryptedBlob).where(EncryptedBlob.id == blob_id)
            )
            blob = result.scalar_one_or_none()
            if blob is None:
                raise NotFoundError("Resource not found")

            # Decrypt with current nonce/tag, re-encrypt with fresh nonce
            plaintext = decrypt_aes_gcm(blob.ciphertext, self._key, blob.nonce, blob.tag)
            new_ct, new_nonce, new_tag = encrypt_aes_gcm(plaintext, self._key)

            blob.ciphertext = new_ct
            blob.nonce = new_nonce
            blob.tag = new_tag
            blob.rotation_count = (blob.rotation_count or 0) + 1
            blob.last_rotated = datetime.now(timezone.utc)
            await session.flush()

        return {
            "blob_id": blob.id,
            "rotation_count": blob.rotation_count,
            "last_rotated": blob.last_rotated.isoformat(),
        }

    async def rotate_all(self) -> dict:
        """Rotate all blobs. Returns count of rotated blobs."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(select(EncryptedBlob))
            blobs = result.scalars().all()

            rotated = 0
            for blob in blobs:
                plaintext = decrypt_aes_gcm(blob.ciphertext, self._key, blob.nonce, blob.tag)
                new_ct, new_nonce, new_tag = encrypt_aes_gcm(plaintext, self._key)
                blob.ciphertext = new_ct
                blob.nonce = new_nonce
                blob.tag = new_tag
                blob.rotation_count = (blob.rotation_count or 0) + 1
                blob.last_rotated = datetime.now(timezone.utc)
                rotated += 1

        return {"rotated": rotated}

    async def detokenize(self, token: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(VaultToken).where(VaultToken.token_value == token)
            )
            vt = result.scalar_one_or_none()
            if vt is None:
                raise NotFoundError("Resource not found")
            if vt.encrypted_value is None:
                raise ValidationError("Token has no encrypted value for detokenization")
            plaintext = decrypt_aes_gcm(
                vt.encrypted_value, self._key, vt.encrypted_nonce, vt.encrypted_tag
            )
        return {"value": plaintext.decode()}
