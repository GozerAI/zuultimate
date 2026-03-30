"""ZuulGuardTool -- C-Suite BaseTool wrapper for ToolGuard."""

from __future__ import annotations

from typing import Any, Dict, List

from csuite.tools.base import BaseTool, ToolCategory, ToolMetadata, ToolParameter, ToolResult


class ZuulGuardTool(BaseTool):
    """Tool that checks whether a tool execution is safe via Zuultimate ToolGuard."""

    def __init__(self, service=None, config=None):
        super().__init__(config)
        self._service = service

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="zuul_guard_check",
            description="Check if a tool execution is permitted (RBAC + injection scan)",
            category=ToolCategory.GENERAL,
            version="0.1.0",
            tags=["security", "guard", "zuultimate"],
        )

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("tool_name", "Name of tool to check", required=True),
            ToolParameter("agent_code", "Executive agent code (e.g. CTO)", required=True),
            ToolParameter("tool_category", "Tool category", required=False, default="general"),
            ToolParameter("parameters", "Tool parameters to scan", required=False, default="{}"),
        ]

    async def _execute(self, **kwargs) -> ToolResult:
        if self._service is None:
            return ToolResult.error_result("Zuultimate service not initialized")

        tool_name = kwargs["tool_name"]
        agent_code = kwargs["agent_code"]
        tool_category = kwargs.get("tool_category", "general")
        params = kwargs.get("parameters", {})
        if isinstance(params, str):
            import json
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {"raw": params}

        decision = await self._service.guard_check(tool_name, agent_code, params, tool_category)
        return ToolResult.success_result({
            "allowed": decision.allowed,
            "reason": decision.reason,
            "stage": decision.stage,
        })
