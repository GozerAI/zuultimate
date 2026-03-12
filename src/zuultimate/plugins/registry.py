"""Plugin registry -- tracks registered plugins."""
from __future__ import annotations
import threading
from typing import Dict, Optional
from zuultimate.plugins.base import BaseZuulPlugin


class PluginRegistry:
    """Thread-safe plugin registry."""

    def __init__(self):
        self._plugins: Dict[str, BaseZuulPlugin] = {}
        self._lock = threading.Lock()

    def register(self, plugin: BaseZuulPlugin) -> None:
        with self._lock:
            self._plugins[plugin.name] = plugin

    def unregister(self, name: str) -> Optional[BaseZuulPlugin]:
        with self._lock:
            return self._plugins.pop(name, None)

    def get(self, name: str) -> Optional[BaseZuulPlugin]:
        with self._lock:
            return self._plugins.get(name)

    def list_plugins(self) -> list[dict]:
        with self._lock:
            return [
                {"name": p.name, "version": p.version, "description": p.description}
                for p in self._plugins.values()
            ]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._plugins)
