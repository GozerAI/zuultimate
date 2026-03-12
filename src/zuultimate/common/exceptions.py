"""Zuultimate exception hierarchy."""


class ZuulError(Exception):
    """Base exception for all Zuultimate errors."""

    def __init__(self, message: str, code: str = "ZUUL_ERROR", status_code: int = 500):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(message)


class AuthenticationError(ZuulError):
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, code="AUTH_ERROR", status_code=401)


class AuthorizationError(ZuulError):
    def __init__(self, message: str = "Access denied"):
        super().__init__(message, code="AUTHZ_ERROR", status_code=403)


class NotFoundError(ZuulError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, code="NOT_FOUND", status_code=404)


class ValidationError(ZuulError):
    def __init__(self, message: str = "Validation failed"):
        super().__init__(message, code="VALIDATION_ERROR", status_code=422)


class SecurityThreatError(ZuulError):
    def __init__(self, message: str = "Security threat detected"):
        super().__init__(message, code="SECURITY_THREAT", status_code=403)
