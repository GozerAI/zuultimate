"""ZuultimateSecurityPlugin -- C-Suite Plugin subclass for AI security integration."""

from __future__ import annotations

from typing import Any, Dict

try:
    from csuite.core.plugins import Plugin, hook
except ImportError as _exc:
    raise ImportError(
        "csuite_plugin requires the 'csuite' package. "
        "Install it or use zuultimate without the C-Suite integration."
    ) from _exc

from zuultimate.ai_security.service import AISecurityService


class ZuultimateSecurityPlugin(Plugin):
    name = "zuultimate-security"
    version = "0.1.0"
    description = "AI Security: ToolGuard, InjectionDetector, Red Team"
    author = "Zuultimate"

    def __init__(self):
        super().__init__()
        self._service: AISecurityService | None = None

    async def on_startup(self) -> None:
        self._service = AISecurityService()

    async def on_shutdown(self) -> None:
        self._service = None

    @property
    def service(self) -> AISecurityService:
        if self._service is None:
            raise RuntimeError("Plugin not started -- call on_startup() first")
        return self._service

    @hook("tool.pre_execute", priority=10)
    async def guard_tool(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Guard tool execution: RBAC + injection scan on parameters."""
        tool_name = event.get("tool_name", "")
        agent_code = event.get("agent_code", "")
        params = event.get("parameters", {})
        tool_category = event.get("tool_category", "general")

        decision = await self.service.guard_check(tool_name, agent_code, params, tool_category)
        if not decision.allowed:
            return {"blocked": True, "reason": decision.reason}
        return {"blocked": False}

    @hook("tool.post_execute", priority=10)
    async def scan_result(self, event: Dict[str, Any]) -> None:
        """Scan tool result for indirect injection."""
        result_text = str(event.get("result", ""))
        agent_code = event.get("agent_code", "")
        if result_text:
            self.service.scan(result_text, agent_code)

    @hook("delegation.pre_execute", priority=10)
    async def guard_delegation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Scan delegation task descriptions for injection."""
        task_text = str(event.get("task", ""))
        agent_code = event.get("agent_code", "")
        if task_text:
            scan_result = self.service.scan(task_text, agent_code)
            if scan_result.is_threat:
                return {"blocked": True, "reason": f"Injection in delegation: score={scan_result.threat_score}"}
        return {"blocked": False}
