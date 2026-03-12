"""FastAPI dependency injection.

Routers create service instances per-request via _get_service(request),
pulling db and settings from request.app.state (set in lifespan).
"""

from zuultimate.common.config import ZuulSettings, get_settings


def get_config() -> ZuulSettings:
    return get_settings()
