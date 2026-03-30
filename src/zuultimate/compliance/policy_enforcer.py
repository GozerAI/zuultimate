"""Automated security policy enforcement engine.

Defines declarative security policies and enforces them against request
contexts, user actions, and system configurations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    REQUIRE_MFA = "require_mfa"
    REQUIRE_APPROVAL = "require_approval"


class PolicySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PolicyViolation:
    policy_id: str
    policy_name: str
    severity: PolicySeverity
    action: PolicyAction
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class PolicyResult:
    allowed: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    matched_policies: list[str] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def highest_severity(self) -> PolicySeverity | None:
        if not self.violations:
            return None
        order = [PolicySeverity.LOW, PolicySeverity.MEDIUM, PolicySeverity.HIGH, PolicySeverity.CRITICAL]
        return max(self.violations, key=lambda v: order.index(v.severity)).severity


@dataclass
class SecurityPolicy:
    id: str
    name: str
    description: str
    severity: PolicySeverity
    action: PolicyAction
    condition: Callable[[dict[str, Any]], bool]
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


class PolicyEnforcer:
    """Evaluates a set of security policies against request/action contexts."""

    def __init__(self) -> None:
        self._policies: dict[str, SecurityPolicy] = {}

    @property
    def policies(self) -> list[SecurityPolicy]:
        return list(self._policies.values())

    def add_policy(self, policy: SecurityPolicy) -> None:
        self._policies[policy.id] = policy

    def remove_policy(self, policy_id: str) -> bool:
        return self._policies.pop(policy_id, None) is not None

    def enable_policy(self, policy_id: str) -> None:
        if policy_id in self._policies:
            self._policies[policy_id].enabled = True

    def disable_policy(self, policy_id: str) -> None:
        if policy_id in self._policies:
            self._policies[policy_id].enabled = False

    def evaluate(self, context: dict[str, Any]) -> PolicyResult:
        violations: list[PolicyViolation] = []
        matched: list[str] = []
        deny = False

        for policy in self._policies.values():
            if not policy.enabled:
                continue
            try:
                triggered = policy.condition(context)
            except Exception:
                continue

            if triggered:
                matched.append(policy.id)
                violations.append(PolicyViolation(
                    policy_id=policy.id, policy_name=policy.name,
                    severity=policy.severity, action=policy.action,
                    message=policy.description, context=context,
                ))
                if policy.action == PolicyAction.DENY:
                    deny = True

        return PolicyResult(allowed=not deny, violations=violations, matched_policies=matched)

    def evaluate_batch(self, contexts: list[dict[str, Any]]) -> list[PolicyResult]:
        return [self.evaluate(ctx) for ctx in contexts]

    def get_policies_by_tag(self, tag: str) -> list[SecurityPolicy]:
        return [p for p in self._policies.values() if tag in p.tags]


def create_default_enforcer() -> PolicyEnforcer:
    """Create an enforcer pre-loaded with standard security policies."""
    enforcer = PolicyEnforcer()

    enforcer.add_policy(SecurityPolicy(
        id="pwd-min-length", name="Password Minimum Length",
        description="Passwords must be at least 12 characters",
        severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
        condition=lambda ctx: "password" in ctx and len(ctx["password"]) < 12,
        tags=["authentication", "password"],
    ))
    enforcer.add_policy(SecurityPolicy(
        id="no-plaintext-secrets", name="No Plaintext Secrets in Payloads",
        description="Request payloads must not contain plaintext secret patterns",
        severity=PolicySeverity.CRITICAL, action=PolicyAction.DENY,
        condition=lambda ctx: any(
            kw in str(ctx.get("payload", "")).lower()
            for kw in ["password=", "secret_key=", "api_key=", "token="]
        ),
        tags=["data-protection"],
    ))
    enforcer.add_policy(SecurityPolicy(
        id="mfa-admin-actions", name="MFA Required for Admin Actions",
        description="Administrative actions require MFA verification",
        severity=PolicySeverity.HIGH, action=PolicyAction.REQUIRE_MFA,
        condition=lambda ctx: ctx.get("action_type") == "admin" and not ctx.get("mfa_verified", False),
        tags=["authentication", "admin"],
    ))
    enforcer.add_policy(SecurityPolicy(
        id="session-max-age", name="Session Maximum Age",
        description="Sessions older than 24 hours must be re-authenticated",
        severity=PolicySeverity.MEDIUM, action=PolicyAction.DENY,
        condition=lambda ctx: "session_age_hours" in ctx and ctx["session_age_hours"] > 24,
        tags=["session"],
    ))
    enforcer.add_policy(SecurityPolicy(
        id="geo-restriction", name="Geographic Access Restriction",
        description="Access denied from restricted geographic regions",
        severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
        condition=lambda ctx: ctx.get("country_code") in ctx.get("blocked_countries", []),
        tags=["access-control", "geo"],
    ))

    return enforcer
