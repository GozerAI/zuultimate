"""PoP FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from pop.cert_validator import CertValidator
from pop.config import PopSettings
from pop.crl_manager import CRLManager
from pop.proxy import PopProxy


def create_pop_app(settings: PopSettings | None = None) -> FastAPI:
    """Create the PoP proxy FastAPI application."""
    settings = settings or PopSettings()

    crl_manager = CRLManager(
        crl_url=settings.crl_url,
        refresh_seconds=settings.crl_refresh_seconds,
    )
    cert_validator = CertValidator(
        ca_cert_path=settings.ca_cert_path,
        crl_manager=crl_manager,
    )
    proxy = PopProxy(
        pop_id=settings.pop_id,
        zuultimate_url=settings.zuultimate_url,
        cert_validator=cert_validator,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.proxy = proxy
        app.state.crl_manager = crl_manager
        yield

    app = FastAPI(
        title="Zuultimate PoP",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "pop_id": settings.pop_id, "region": settings.region}

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    async def proxy_request(path: str, request: Request):
        """Proxy all requests to zuultimate with posture headers."""
        cert_pem = request.headers.get("X-Client-Cert", "")

        if not cert_pem:
            return Response(
                content='{"error":"Missing client certificate"}',
                status_code=401,
                media_type="application/json",
            )

        try:
            headers = proxy.build_upstream_headers(cert_pem)
        except ValueError as exc:
            return Response(
                content=f'{{"error":"{exc}"}}',
                status_code=403,
                media_type="application/json",
            )

        # In production: forward to zuultimate_url using httpx
        # For now: return the headers that would be sent
        return {
            "proxied_to": f"{settings.zuultimate_url}/{path}",
            "upstream_headers": headers,
        }

    return app
