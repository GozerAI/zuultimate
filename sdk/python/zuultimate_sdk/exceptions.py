"""Typed exceptions for Zuultimate API errors."""


class ZuultimateError(Exception):
    """Base exception for all Zuultimate API errors."""

    def __init__(self, message: str, status_code: int = 0, code: str = ""):
        self.message = message
        self.status_code = status_code
        self.code = code
        super().__init__(message)


class AuthenticationError(ZuultimateError):
    """Raised when authentication fails (401)."""

    pass


class NotFoundError(ZuultimateError):
    """Raised when a resource is not found (404)."""

    pass


class ValidationError(ZuultimateError):
    """Raised when request validation fails (422)."""

    pass


class RateLimitError(ZuultimateError):
    """Raised when the API rate limit is exceeded (429)."""

    pass
