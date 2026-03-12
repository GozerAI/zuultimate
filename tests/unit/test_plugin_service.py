"""Unit tests for PluginService."""

import pytest

from zuultimate.plugins.base import BaseZuulPlugin
from zuultimate.plugins.registry import PluginRegistry
from zuultimate.plugins.service import PluginService


class _FakePlugin(BaseZuulPlugin):
    name = "fake"
    version = "1.0.0"
    description = "A fake plugin for testing"

    def __init__(self):
        self.started = False
        self.stopped = False
        self.last_webhook = None

    async def on_startup(self):
        self.started = True

    async def on_shutdown(self):
        self.stopped = True

    async def handle_webhook(self, payload):
        self.last_webhook = payload
        return {"received": True}


class _AnotherPlugin(BaseZuulPlugin):
    name = "another"
    version = "0.1.0"
    description = "Another fake plugin"

    async def on_startup(self):
        pass

    async def on_shutdown(self):
        pass


@pytest.fixture
def svc():
    return PluginService()


async def test_register_plugin(svc):
    plugin = _FakePlugin()
    await svc.register_plugin(plugin)
    assert plugin.started is True
    assert svc.registry.get("fake") is plugin


async def test_unregister_plugin(svc):
    plugin = _FakePlugin()
    await svc.register_plugin(plugin)
    result = await svc.unregister_plugin("fake")
    assert result is True
    assert plugin.stopped is True
    assert svc.registry.get("fake") is None


async def test_unregister_nonexistent(svc):
    result = await svc.unregister_plugin("nope")
    assert result is False


async def test_list_plugins_empty(svc):
    assert svc.list_plugins() == []


async def test_list_plugins(svc):
    await svc.register_plugin(_FakePlugin())
    await svc.register_plugin(_AnotherPlugin())
    items = svc.list_plugins()
    assert len(items) == 2
    names = {p["name"] for p in items}
    assert names == {"fake", "another"}


async def test_handle_webhook(svc):
    plugin = _FakePlugin()
    await svc.register_plugin(plugin)
    result = await svc.handle_webhook("fake", {"event": "push"})
    assert result == {"received": True}
    assert plugin.last_webhook == {"event": "push"}


async def test_handle_webhook_not_found(svc):
    result = await svc.handle_webhook("missing", {"event": "push"})
    assert "error" in result


async def test_custom_registry():
    registry = PluginRegistry()
    svc = PluginService(registry=registry)
    plugin = _FakePlugin()
    await svc.register_plugin(plugin)
    assert registry.count == 1
    assert registry.get("fake") is plugin
