"""Abstract base class for Zuultimate plugins."""
from abc import ABC, abstractmethod
from typing import Any


class BaseZuulPlugin(ABC):
    """Base class for all Zuultimate plugins."""

    name: str = "unnamed"
    version: str = "0.0.0"
    description: str = ""

    @abstractmethod
    async def on_startup(self) -> None:
        """Called when plugin starts."""
        ...

    @abstractmethod
    async def on_shutdown(self) -> None:
        """Called when plugin shuts down."""
        ...

    async def handle_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle incoming webhook. Override to implement."""
        return {"status": "not_implemented"}
