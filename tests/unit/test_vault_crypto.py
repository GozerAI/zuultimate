"""Tests for zuultimate.vault.crypto -- AES-256-GCM encrypt/decrypt + key derivation."""

from __future__ import annotations

import os

import pytest

from zuultimate.vault.crypto import decrypt_aes_gcm, derive_key, encrypt_aes_gcm

PLAINTEXT = b"Hello, Zuultimate!"


# ---------------------------------------------------------------------------
# Encrypt / decrypt round-trip
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    ciphertext, nonce, tag = encrypt_aes_gcm(PLAINTEXT, key)
    result = decrypt_aes_gcm(ciphertext, key, nonce, tag)
    assert result == PLAINTEXT


# ---------------------------------------------------------------------------
# Nonce uniqueness
# ---------------------------------------------------------------------------


def test_encrypt_produces_different_nonces():
    key = os.urandom(32)
    _, nonce1, _ = encrypt_aes_gcm(PLAINTEXT, key)
    _, nonce2, _ = encrypt_aes_gcm(PLAINTEXT, key)
    assert nonce1 != nonce2


# ---------------------------------------------------------------------------
# Wrong key
# ---------------------------------------------------------------------------


def test_decrypt_wrong_key_fails():
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    ciphertext, nonce, tag = encrypt_aes_gcm(PLAINTEXT, key)
    with pytest.raises(Exception):
        decrypt_aes_gcm(ciphertext, wrong_key, nonce, tag)


# ---------------------------------------------------------------------------
# Tampered ciphertext
# ---------------------------------------------------------------------------


def test_decrypt_tampered_ciphertext_fails():
    key = os.urandom(32)
    ciphertext, nonce, tag = encrypt_aes_gcm(PLAINTEXT, key)
    # Flip the first bit of the ciphertext
    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    with pytest.raises(Exception):
        decrypt_aes_gcm(tampered, key, nonce, tag)


# ---------------------------------------------------------------------------
# Key length validation
# ---------------------------------------------------------------------------


def test_key_must_be_32_bytes():
    short_key = os.urandom(16)
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt_aes_gcm(PLAINTEXT, short_key)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def test_derive_key_produces_32_bytes():
    key, salt = derive_key("my-password")
    assert len(key) == 32
    assert isinstance(salt, bytes)
    assert len(salt) > 0


def test_derive_key_deterministic_with_salt():
    _, salt = derive_key("my-password")
    key1, _ = derive_key("my-password", salt=salt)
    key2, _ = derive_key("my-password", salt=salt)
    assert key1 == key2


def test_derive_key_different_salts():
    salt_a = os.urandom(16)
    salt_b = os.urandom(16)
    key_a, _ = derive_key("my-password", salt=salt_a)
    key_b, _ = derive_key("my-password", salt=salt_b)
    assert key_a != key_b
