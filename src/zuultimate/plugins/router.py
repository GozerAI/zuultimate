"""FastAPI router for plugin management endpoints."""
from __future__ import annotations
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from zuultimate.common.auth import get_current_user
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.plugins.service import PluginService

router = APIRouter(
    prefix="/plugins",
    tags=["plugins"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


class PluginRegistrationRequest(BaseModel):
    name: str
    version: str = "0.0.0"
    description: str = ""


def _get_service(request: Request) -> PluginService:
    """Return or create the per-app PluginService instance."""
    svc = getattr(request.app.state, "_plugin_service", None)
    if svc is None:
        svc = PluginService()
        request.app.state._plugin_service = svc
    return svc


@router.get("/", summary="List registered plugins")
async def list_plugins(request: Request) -> list[dict]:
    """List all registered plugins."""
    svc = _get_service(request)
    return svc.list_plugins()


@router.post("/register", summary="Register plugin (stub)", status_code=501)
async def register_plugin_via_api(body: PluginRegistrationRequest) -> dict[str, str]:
    """Plugin registration via API is not supported.

    Plugins must be registered at the code level using PluginService.register_plugin().
    """
    return {"detail": "Plugin registration via API not supported"}


@router.get("/{plugin_id}", summary="Get plugin details")
async def get_plugin(plugin_id: str, request: Request) -> dict:
    """Get information about a specific plugin by name."""
    svc = _get_service(request)
    plugin = svc.registry.get(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {
        "name": plugin.name,
        "version": plugin.version,
        "description": plugin.description,
    }


@router.post("/{plugin_id}/webhook", summary="Forward webhook to plugin")
async def plugin_webhook(
    plugin_id: str, payload: dict[str, Any], request: Request
) -> dict[str, Any]:
    """Forward a webhook payload to the specified plugin."""
    svc = _get_service(request)
    result = await svc.handle_webhook(plugin_id, payload)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
