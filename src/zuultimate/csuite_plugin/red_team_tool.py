"""ZuulRedTeamTool -- C-Suite BaseTool wrapper for red team testing."""

from __future__ import annotations

from typing import List

from csuite.tools.base import BaseTool, ToolCategory, ToolMetadata, ToolParameter, ToolResult


class ZuulRedTeamTool(BaseTool):
    """Tool that runs adversarial red team tests against the injection detector."""

    def __init__(self, service=None, config=None):
        super().__init__(config)
        self._service = service

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="zuul_redteam",
            description="Run adversarial red team tests (passphrase required)",
            category=ToolCategory.GENERAL,
            version="0.1.0",
            tags=["security", "redteam", "zuultimate"],
            requires_auth=True,
        )

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("passphrase", "Red team passphrase", required=True),
            ToolParameter("categories", "Attack categories to test", required=False, default=None),
        ]

    async def _execute(self, **kwargs) -> ToolResult:
        if self._service is None:
            return ToolResult.error_result("Zuultimate service not initialized")

        passphrase = kwargs["passphrase"]
        categories = kwargs.get("categories")

        try:
            result = await self._service.red_team_execute(passphrase, categories)
        except PermissionError:
            return ToolResult.error_result("Red team authentication failed", "AuthError")

        return ToolResult.success_result({
            "total_attacks": result.total_attacks,
            "detected": result.detected,
            "bypassed": result.bypassed,
            "detection_rate": result.detection_rate,
            "bypassed_payloads": result.bypassed_payloads,
        })
