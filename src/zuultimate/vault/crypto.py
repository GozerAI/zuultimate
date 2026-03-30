"""AES-256-GCM encryption/decryption + argon2id key derivation."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# argon2 key derivation
from argon2.low_level import Type, hash_secret_raw


def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (ciphertext, nonce, tag)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM appends the tag to ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, nonce, tag


def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, None)


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive 32-byte key from password using argon2id. Returns (key, salt)."""
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    return key, salt
