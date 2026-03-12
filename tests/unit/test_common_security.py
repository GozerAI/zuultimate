"""Tests for zuultimate.common.security -- password hashing and JWT tokens."""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from zuultimate.common.security import create_jwt, decode_jwt, hash_password, verify_password

SECRET = "test-secret-key"


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def test_hash_and_verify():
    hashed = hash_password("test")
    assert verify_password("test", hashed) is True


def test_verify_wrong_password():
    hashed = hash_password("test")
    assert verify_password("wrong", hashed) is False


def test_hash_not_plaintext():
    hashed = hash_password("test")
    assert hashed != "test"


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------


def test_create_and_decode_jwt():
    token = create_jwt({"sub": "user1"}, SECRET)
    payload = decode_jwt(token, SECRET)
    assert payload["sub"] == "user1"


def test_decode_expired_jwt():
    token = create_jwt({"sub": "user1"}, SECRET, expires_minutes=0)
    # Wait a moment so the token is definitely expired
    time.sleep(1)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_jwt(token, SECRET)


def test_decode_wrong_key():
    token = create_jwt({"sub": "user1"}, SECRET)
    with pytest.raises(Exception):
        decode_jwt(token, "wrong-key")
