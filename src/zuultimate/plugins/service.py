"""Plugin service -- lifecycle management."""
from __future__ import annotations
from zuultimate.plugins.base import BaseZuulPlugin
from zuultimate.plugins.registry import PluginRegistry


class PluginService:
    def __init__(self, registry: PluginRegistry | None = None):
        self.registry = registry or PluginRegistry()

    async def register_plugin(self, plugin: BaseZuulPlugin) -> None:
        self.registry.register(plugin)
        await plugin.on_startup()

    async def unregister_plugin(self, name: str) -> bool:
        plugin = self.registry.unregister(name)
        if plugin:
            await plugin.on_shutdown()
            return True
        return False

    async def handle_webhook(self, plugin_name: str, payload: dict) -> dict:
        plugin = self.registry.get(plugin_name)
        if not plugin:
            return {"error": f"Plugin '{plugin_name}' not found"}
        return await plugin.handle_webhook(payload)

    def list_plugins(self) -> list[dict]:
        return self.registry.list_plugins()
