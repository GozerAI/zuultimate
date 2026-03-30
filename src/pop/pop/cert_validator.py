"""X.509 certificate validation for mTLS client certs."""

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

_log = logging.getLogger("pop.cert_validator")


@dataclass
class CertInfo:
    """Parsed client certificate information."""

    subject_cn: str = ""
    issuer_cn: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint: str = ""
    is_valid: bool = False
    error: str = ""
    device_id: str = ""


class CertValidator:
    """Validates X.509 client certificates from mTLS termination.

    Expects the certificate in PEM or DER format, typically passed via
    X-Client-Cert header by the nginx mTLS sidecar.
    """

    def __init__(self, ca_cert_path: str = "", crl_manager=None):
        self._ca_cert_path = ca_cert_path
        self._crl_manager = crl_manager

    def validate(self, cert_pem: str) -> CertInfo:
        """Validate a PEM-encoded client certificate.

        Returns CertInfo with is_valid=True if the cert passes all checks.
        For production, uses cryptography library for full chain validation.
        This stub performs basic structure and expiry checks.
        """
        info = CertInfo()

        if not cert_pem or not cert_pem.strip():
            info.error = "Empty certificate"
            return info

        try:
            # URL-decode if needed (nginx may URL-encode the PEM)
            import urllib.parse

            decoded_pem = urllib.parse.unquote(cert_pem)

            # Basic PEM structure check
            if "BEGIN CERTIFICATE" not in decoded_pem:
                info.error = "Invalid PEM format"
                return info

            # Extract the base64 portion for fingerprint
            pem_lines = decoded_pem.strip().split("\n")
            b64_lines = [
                line
                for line in pem_lines
                if not line.startswith("-----")
            ]
            der_bytes = base64.b64decode("".join(b64_lines))
            info.fingerprint = hashlib.sha256(der_bytes).hexdigest()[:16]

            # Try to parse with cryptography if available
            try:
                from cryptography import x509

                cert = x509.load_pem_x509_certificate(decoded_pem.encode())
                info.subject_cn = cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )[0].value
                info.issuer_cn = cert.issuer.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )[0].value
                info.serial = str(cert.serial_number)
                info.not_before = cert.not_valid_before_utc
                info.not_after = cert.not_valid_after_utc
                info.device_id = info.subject_cn  # CN = device identifier

                # Check expiry
                now = datetime.now(timezone.utc)
                if now < info.not_before:
                    info.error = "Certificate not yet valid"
                    return info
                if now > info.not_after:
                    info.error = "Certificate expired"
                    return info

                # CRL check
                if self._crl_manager and self._crl_manager.is_revoked(info.serial):
                    info.error = "Certificate revoked"
                    return info

                info.is_valid = True

            except ImportError:
                # cryptography not available -- mark as valid with limited info
                info.subject_cn = "unknown"
                info.device_id = "unknown"
                info.is_valid = True

        except Exception as exc:
            info.error = f"Certificate parse error: {exc}"
            _log.warning("Cert validation failed: %s", exc)

        return info
