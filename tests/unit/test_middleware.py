"""Unit tests for request ID middleware and correlation logging."""

import pytest
from httpx import ASGITransport, AsyncClient

from zuultimate.common.logging import request_id_var


@pytest.fixture
def simple_app():
    """Minimal FastAPI app with RequestIDMiddleware for isolated testing."""
    from fastapi import FastAPI
    from zuultimate.common.middleware import RequestIDMiddleware

    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)

    @app.get("/echo")
    async def echo():
        return {"request_id": request_id_var.get()}

    return app


async def test_middleware_generates_request_id(simple_app):
    transport = ASGITransport(app=simple_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/echo")

    assert resp.status_code == 200
    # Response must contain X-Request-ID header
    req_id = resp.headers.get("x-request-id")
    assert req_id is not None
    assert len(req_id) == 16  # uuid4().hex[:16]


async def test_middleware_preserves_client_request_id(simple_app):
    transport = ASGITransport(app=simple_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/echo", headers={"X-Request-ID": "my-trace-abc"})

    assert resp.headers.get("x-request-id") == "my-trace-abc"
    assert resp.json()["request_id"] == "my-trace-abc"


async def test_middleware_unique_ids_per_request(simple_app):
    transport = ASGITransport(app=simple_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r1 = await ac.get("/echo")
        r2 = await ac.get("/echo")

    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
