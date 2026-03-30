"""PoP proxy: validates certs, signs posture blobs, forwards to zuultimate."""

import hashlib
import hmac
import json
import logging
from dataclasses import asdict

from pop.cert_validator import CertValidator

_log = logging.getLogger("pop.proxy")


class PopProxy:
    """Stateless proxy that validates client certs and enriches upstream requests.

    Flow:
    1. Receive request with X-Client-Cert header (from nginx mTLS sidecar)
    2. Validate certificate chain
    3. Extract device_id from CN
    4. Build posture blob
    5. Sign posture blob with PoP private key
    6. Forward to zuultimate with X-Device-ID, X-Posture-Blob, X-Pop-Signature
    """

    def __init__(
        self,
        pop_id: str,
        zuultimate_url: str,
        cert_validator: CertValidator,
        signing_key: str = "",
    ):
        self.pop_id = pop_id
        self.zuultimate_url = zuultimate_url
        self.cert_validator = cert_validator
        self._signing_key = signing_key

    def build_posture_blob(self, cert_info, extra: dict | None = None) -> str:
        """Build a JSON posture blob from cert info and optional extra data."""
        blob = {
            "device_id": cert_info.device_id,
            "cert_fingerprint": cert_info.fingerprint,
            "cert_valid": cert_info.is_valid,
            "pop_id": self.pop_id,
        }
        if extra:
            blob.update(extra)
        return json.dumps(blob, sort_keys=True)

    def sign_blob(self, blob: str) -> str:
        """HMAC-SHA256 sign the posture blob with the PoP signing key."""
        if not self._signing_key:
            return ""
        return hmac.new(
            self._signing_key.encode(), blob.encode(), hashlib.sha256
        ).hexdigest()

    def build_upstream_headers(
        self, cert_pem: str, extra_posture: dict | None = None
    ) -> dict:
        """Validate cert and build upstream headers for zuultimate.

        Returns a dict of headers to attach to the upstream request.
        Raises ValueError if cert validation fails.
        """
        cert_info = self.cert_validator.validate(cert_pem)
        if not cert_info.is_valid:
            raise ValueError(f"Certificate validation failed: {cert_info.error}")

        blob = self.build_posture_blob(cert_info, extra_posture)
        signature = self.sign_blob(blob)

        return {
            "X-Device-ID": cert_info.device_id,
            "X-Posture-Blob": blob,
            "X-Pop-Signature": signature,
            "X-Pop-ID": self.pop_id,
        }
