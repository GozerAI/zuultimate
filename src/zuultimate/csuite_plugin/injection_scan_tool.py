"""ZuulScanTool -- C-Suite BaseTool wrapper for InjectionDetector."""

from __future__ import annotations

from typing import List

from csuite.tools.base import BaseTool, ToolCategory, ToolMetadata, ToolParameter, ToolResult


class ZuulScanTool(BaseTool):
    """Tool that scans text for prompt injection / jailbreak threats."""

    def __init__(self, service=None, config=None):
        super().__init__(config)
        self._service = service

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="zuul_injection_scan",
            description="Scan text for prompt injection, jailbreak, and exfiltration threats",
            category=ToolCategory.GENERAL,
            version="0.1.0",
            tags=["security", "injection", "zuultimate"],
        )

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("text", "Text to scan for threats", required=True),
            ToolParameter("agent_code", "Agent code for audit trail", required=False, default=""),
        ]

    async def _execute(self, **kwargs) -> ToolResult:
        if self._service is None:
            return ToolResult.error_result("Zuultimate service not initialized")

        text = kwargs["text"]
        agent_code = kwargs.get("agent_code", "")
        result = self._service.scan(text, agent_code)

        return ToolResult.success_result({
            "is_threat": result.is_threat,
            "threat_score": result.threat_score,
            "detections": [
                {
                    "pattern": d.pattern_name,
                    "category": d.category.value,
                    "severity": d.severity.value,
                    "match": d.matched_text[:100],
                }
                for d in result.detections
            ],
            "heuristic_flags": result.heuristic_flags,
        })
