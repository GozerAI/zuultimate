"""Security utilities: password hashing, JWT tokens (RS256 + HS256 fallback)."""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()
_ISSUER = "zuultimate"
_AUDIENCE = "zuultimate-api"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except VerifyMismatchError:
        return False


def create_jwt(
    payload: dict,
    secret_key: str,
    expires_minutes: int = 60,
    *,
    private_key: str | None = None,
    kid: str | None = None,
) -> str:
    """Create a JWT token.

    If private_key and kid are provided, signs with RS256 and includes kid in header.
    Otherwise falls back to HS256 with secret_key (legacy behavior).
    """
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    data["iat"] = datetime.now(timezone.utc)
    data["jti"] = uuid.uuid4().hex
    data["iss"] = _ISSUER
    data["aud"] = _AUDIENCE

    if private_key and kid:
        return jwt.encode(
            data, private_key, algorithm="RS256", headers={"kid": kid}
        )

    return jwt.encode(data, secret_key, algorithm="HS256")


def decode_jwt(
    token: str,
    secret_key: str,
    verify_exp: bool = True,
    *,
    public_keys: dict[str, str] | None = None,
) -> dict:
    """Decode and verify a JWT token.

    If public_keys is provided ({kid: public_key_pem}), extracts kid from header
    and verifies with RS256. Otherwise falls back to HS256 with secret_key.
    """
    options = {"verify_exp": verify_exp}

    if public_keys:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid or kid not in public_keys:
            raise jwt.InvalidTokenError(f"Unknown kid: {kid}")

        return jwt.decode(
            token,
            public_keys[kid],
            algorithms=["RS256"],
            options=options,
            issuer=_ISSUER,
            audience=_AUDIENCE,
        )

    return jwt.decode(
        token,
        secret_key,
        algorithms=["HS256"],
        options=options,
        issuer=_ISSUER,
        audience=_AUDIENCE,
    )
