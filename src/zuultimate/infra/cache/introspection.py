"""Lightweight JWT introspection helpers for bloom filter pre-screening."""

import base64
import json


def extract_jti_from_token(token: str) -> str | None:
    """
    Extract JTI from JWT without full signature verification.
    Used for bloom filter pre-screening only -- full verification happens after.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Decode payload (base64url, no verification)
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        return payload.get("jti")
    except Exception:
        return None
