"""FastAPI dependency injection.

Service instances are created per-request in each router via _get_service(request),
using request.app.state.db and request.app.state.settings from the lifespan.
This module provides shared utilities only.
"""

from zuultimate.common.config import ZuulSettings, get_settings


def get_config() -> ZuulSettings:
    return get_settings()
