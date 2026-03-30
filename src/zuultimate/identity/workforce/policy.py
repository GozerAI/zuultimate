"""Attribute-Based Access Control policy engine for workforce access."""

import enum
from dataclasses import dataclass, field


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"


@dataclass
class WorkforceContext:
    user_id: str = ""
    tenant_id: str = ""
    device_id: str = ""
    # Cert/device posture
    cert_valid: bool = False
    mdm_enrolled: bool = False
    disk_encrypted: bool = False
    posture_score: float = 0.0
    # Request context
    resource: str = ""
    action: str = ""
    sovereignty_ring: str = "us"
    session_age_minutes: int = 0
    is_off_hours: bool = False
    # Sensitivity
    sensitivity: str = "normal"  # normal | high
    has_jit_grant: bool = False
    jit_scope: str = ""


@dataclass
class PolicyResult:
    decision: Decision
    reason: str = ""
    required_scopes: list[str] = field(default_factory=list)
    ttl_seconds: int = 3600


class WorkforceAccessPolicy:
    """Evaluates workforce access requests against ABAC policies."""

    def evaluate(self, ctx: WorkforceContext) -> PolicyResult:
        # Mandatory checks
        if not ctx.cert_valid:
            return PolicyResult(Decision.DENY, "Invalid or missing client certificate")
        if not ctx.mdm_enrolled:
            return PolicyResult(Decision.DENY, "Device not enrolled in MDM")
        if not ctx.disk_encrypted:
            return PolicyResult(Decision.DENY, "Disk encryption required")

        # Risk-adaptive
        if ctx.posture_score > 0.85:
            return PolicyResult(
                Decision.DENY, f"Posture score too high: {ctx.posture_score}"
            )
        if ctx.posture_score > 0.6:
            return PolicyResult(
                Decision.STEP_UP, f"Elevated risk: {ctx.posture_score}"
            )

        # Sovereignty
        if ctx.resource.startswith("us_only:") and ctx.sovereignty_ring != "us":
            if not ctx.has_jit_grant:
                return PolicyResult(
                    Decision.DENY,
                    "US-only resource requires JIT grant for non-US access",
                )

        # Sensitivity checks
        if ctx.sensitivity == "high":
            if ctx.session_age_minutes > 30:
                return PolicyResult(
                    Decision.STEP_UP,
                    "Session too old for high-sensitivity resource",
                )
            if ctx.is_off_hours:
                return PolicyResult(
                    Decision.STEP_UP,
                    "Off-hours access to high-sensitivity resource",
                )

        # Compute TTL
        ttl = self._compute_ttl(ctx)
        scopes = self._compute_scopes(ctx)

        return PolicyResult(Decision.ALLOW, "Access granted", scopes, ttl)

    def _compute_scopes(self, ctx: WorkforceContext) -> list[str]:
        scopes = ["workforce:read"]
        if ctx.posture_score < 0.3 and ctx.mdm_enrolled:
            scopes.append("workforce:write")
        if ctx.has_jit_grant:
            scopes.append(ctx.jit_scope)
        return scopes

    def _compute_ttl(self, ctx: WorkforceContext) -> int:
        if ctx.sensitivity == "high":
            return 900  # 15 min
        if ctx.posture_score > 0.4:
            return 1800  # 30 min
        return 3600  # 1 hour
