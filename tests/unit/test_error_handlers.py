"""Unit tests for global error handlers."""

import pytest
from httpx import ASGITransport, AsyncClient

from zuultimate.common.exceptions import NotFoundError, SecurityThreatError


@pytest.fixture
def error_app():
    """App with routes that raise various exceptions for handler testing."""
    from fastapi import FastAPI, Request
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel

    from zuultimate.common.exceptions import ZuulError
    from zuultimate.common.logging import get_logger
    from zuultimate.common.schemas import ErrorResponse

    _log = get_logger("test")

    app = FastAPI()

    @app.exception_handler(ZuulError)
    async def _zuul_error(request: Request, exc: ZuulError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(error=exc.message, code=exc.code).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="Validation failed",
                code="VALIDATION_ERROR",
                detail=str(exc.errors()),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal server error", code="INTERNAL_ERROR"
            ).model_dump(),
        )

    @app.get("/raise-not-found")
    async def raise_not_found():
        raise NotFoundError("thing not found")

    @app.get("/raise-security")
    async def raise_security():
        raise SecurityThreatError("injection detected")

    @app.get("/raise-unhandled")
    async def raise_unhandled():
        raise RuntimeError("something broke")

    class StrictBody(BaseModel):
        value: int

    @app.post("/validate")
    async def validate(body: StrictBody):
        return {"ok": True}

    return app


async def test_zuul_error_handler_not_found(error_app):
    transport = ASGITransport(app=error_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/raise-not-found")
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"] == "thing not found"
    assert body["code"] == "NOT_FOUND"


async def test_zuul_error_handler_security(error_app):
    transport = ASGITransport(app=error_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/raise-security")
    assert resp.status_code == 403
    body = resp.json()
    assert body["code"] == "SECURITY_THREAT"


async def test_validation_error_handler(error_app):
    transport = ASGITransport(app=error_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/validate", json={"value": "not_int"})
    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert body["detail"] is not None


async def test_unhandled_exception_returns_500(error_app):
    """Unhandled exceptions return 500 via Starlette's ServerErrorMiddleware."""
    transport = ASGITransport(app=error_app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/raise-unhandled")
    assert resp.status_code == 500
