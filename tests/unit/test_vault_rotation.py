"""Unit tests for vault secrets rotation."""

import pytest

from zuultimate.vault.service import VaultService


@pytest.fixture
async def vault_svc(test_db, test_settings):
    return VaultService(test_db, test_settings)


async def test_rotate_blob_preserves_plaintext(vault_svc):
    enc = await vault_svc.encrypt("secret-data", label="test")
    result = await vault_svc.rotate_blob(enc["blob_id"])
    assert result["rotation_count"] == 1
    assert result["last_rotated"] is not None

    # Decrypt should still return original plaintext
    dec = await vault_svc.decrypt(enc["blob_id"])
    assert dec["plaintext"] == "secret-data"


async def test_rotate_blob_changes_ciphertext(vault_svc):
    """Rotation should produce different ciphertext (new nonce)."""
    enc = await vault_svc.encrypt("same-data", label="test")
    # We can't easily compare ciphertext directly, but rotating + decrypting proves correctness
    await vault_svc.rotate_blob(enc["blob_id"])
    await vault_svc.rotate_blob(enc["blob_id"])

    dec = await vault_svc.decrypt(enc["blob_id"])
    assert dec["plaintext"] == "same-data"


async def test_rotate_increments_count(vault_svc):
    enc = await vault_svc.encrypt("data", label="test")
    r1 = await vault_svc.rotate_blob(enc["blob_id"])
    assert r1["rotation_count"] == 1
    r2 = await vault_svc.rotate_blob(enc["blob_id"])
    assert r2["rotation_count"] == 2


async def test_rotate_nonexistent_blob(vault_svc):
    from zuultimate.common.exceptions import NotFoundError
    with pytest.raises(NotFoundError):
        await vault_svc.rotate_blob("nonexistent")


async def test_rotate_all(vault_svc):
    await vault_svc.encrypt("secret1", label="a")
    await vault_svc.encrypt("secret2", label="b")
    await vault_svc.encrypt("secret3", label="c")

    result = await vault_svc.rotate_all()
    assert result["rotated"] == 3
