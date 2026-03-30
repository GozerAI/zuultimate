"""Unit tests for VaultService."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.vault.service import VaultService


@pytest.fixture
def svc(test_db, test_settings):
    return VaultService(test_db, test_settings)


# ---------------------------------------------------------------------------
# encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------


async def test_encrypt_returns_blob_id(svc):
    result = await svc.encrypt("hello world", label="greeting", owner_id="user1")
    assert "blob_id" in result
    assert result["label"] == "greeting"


async def test_encrypt_decrypt_roundtrip(svc):
    enc = await svc.encrypt("secret data", label="test")
    dec = await svc.decrypt(enc["blob_id"])
    assert dec["plaintext"] == "secret data"


async def test_encrypt_empty_plaintext_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.encrypt("")


async def test_decrypt_not_found(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.decrypt("nonexistent-blob-id")


async def test_encrypt_different_data_different_blobs(svc):
    a = await svc.encrypt("data-a")
    b = await svc.encrypt("data-b")
    assert a["blob_id"] != b["blob_id"]


async def test_encrypt_same_data_different_blobs(svc):
    a = await svc.encrypt("same")
    b = await svc.encrypt("same")
    assert a["blob_id"] != b["blob_id"]  # Not idempotent for blobs


# ---------------------------------------------------------------------------
# tokenize / detokenize
# ---------------------------------------------------------------------------


async def test_tokenize_returns_token(svc):
    result = await svc.tokenize("4111111111111111")
    assert result["token"].startswith("tok_")


async def test_tokenize_detokenize_roundtrip(svc):
    tok = await svc.tokenize("sensitive-value")
    det = await svc.detokenize(tok["token"])
    assert det["value"] == "sensitive-value"


async def test_tokenize_idempotent(svc):
    t1 = await svc.tokenize("same-value")
    t2 = await svc.tokenize("same-value")
    assert t1["token"] == t2["token"]


async def test_tokenize_empty_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.tokenize("")


async def test_detokenize_not_found(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.detokenize("tok_nonexistent")


async def test_tokenize_different_values_different_tokens(svc):
    t1 = await svc.tokenize("value-a")
    t2 = await svc.tokenize("value-b")
    assert t1["token"] != t2["token"]
