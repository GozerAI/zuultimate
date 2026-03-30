"""Automated compliance report generation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ReportType(str, Enum):
    SECURITY_POSTURE = "security_posture"
    PII_EXPOSURE = "pii_exposure"
    CONSENT_STATUS = "consent_status"
    DSAR_METRICS = "dsar_metrics"
    POLICY_COMPLIANCE = "policy_compliance"
    FULL_AUDIT = "full_audit"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"


@dataclass
class ComplianceCheck:
    check_id: str
    name: str
    description: str
    status: ComplianceStatus
    details: str = ""
    remediation: str = ""
    framework: str = ""


@dataclass
class ComplianceSection:
    title: str
    checks: list[ComplianceCheck] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.COMPLIANT)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.NON_COMPLIANT)

    @property
    def compliance_rate(self) -> float:
        total = len(self.checks)
        if total == 0:
            return 1.0
        return self.pass_count / total


@dataclass
class ComplianceReport:
    report_id: str
    report_type: ReportType
    generated_at: str
    tenant_id: str
    sections: list[ComplianceSection] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def overall_status(self) -> ComplianceStatus:
        if not self.sections:
            return ComplianceStatus.NOT_ASSESSED
        all_checks = [c for s in self.sections for c in s.checks]
        if not all_checks:
            return ComplianceStatus.NOT_ASSESSED
        if all(c.status == ComplianceStatus.COMPLIANT for c in all_checks):
            return ComplianceStatus.COMPLIANT
        if any(c.status == ComplianceStatus.NON_COMPLIANT for c in all_checks):
            return ComplianceStatus.NON_COMPLIANT
        return ComplianceStatus.PARTIALLY_COMPLIANT

    @property
    def total_checks(self) -> int:
        return sum(len(s.checks) for s in self.sections)

    @property
    def overall_compliance_rate(self) -> float:
        total = self.total_checks
        if total == 0:
            return 1.0
        passed = sum(s.pass_count for s in self.sections)
        return passed / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "generated_at": self.generated_at,
            "tenant_id": self.tenant_id,
            "overall_status": self.overall_status.value,
            "overall_compliance_rate": round(self.overall_compliance_rate, 4),
            "total_checks": self.total_checks,
            "sections": [
                {
                    "title": s.title,
                    "compliance_rate": round(s.compliance_rate, 4),
                    "pass_count": s.pass_count,
                    "fail_count": s.fail_count,
                    "checks": [
                        {
                            "check_id": c.check_id, "name": c.name,
                            "status": c.status.value, "details": c.details,
                            "remediation": c.remediation, "framework": c.framework,
                        }
                        for c in s.checks
                    ],
                }
                for s in self.sections
            ],
            "metadata": self.metadata,
        }


class ComplianceReportGenerator:
    """Generates compliance reports from system state."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._sections: dict[str, ComplianceSection] = {}
        self._report_counter = 0

    def add_section(self, title: str) -> ComplianceSection:
        if title not in self._sections:
            self._sections[title] = ComplianceSection(title=title)
        return self._sections[title]

    def add_check(self, section_title: str, check: ComplianceCheck) -> None:
        section = self.add_section(section_title)
        section.checks.append(check)

    def generate(
        self,
        report_type: ReportType = ReportType.FULL_AUDIT,
        metadata: dict[str, Any] | None = None,
    ) -> ComplianceReport:
        self._report_counter += 1
        report_id = f"rpt-{self.tenant_id}-{self._report_counter}-{int(time.time())}"
        return ComplianceReport(
            report_id=report_id, report_type=report_type,
            generated_at=datetime.now(timezone.utc).isoformat(),
            tenant_id=self.tenant_id,
            sections=list(self._sections.values()),
            metadata=metadata or {},
        )

    def clear(self) -> None:
        self._sections.clear()

    def run_security_posture_checks(
        self, *, mfa_enabled: bool = False, password_policy_enforced: bool = False,
        encryption_at_rest: bool = False, audit_logging: bool = False,
        ip_allowlisting: bool = False, session_timeout_configured: bool = False,
    ) -> ComplianceReport:
        self.clear()
        checks = [
            ("sp-mfa", "MFA Enabled", "Multi-factor authentication is enabled for all users",
             mfa_enabled, "Enable MFA for all user accounts", "SOC2"),
            ("sp-pwd", "Password Policy", "Password complexity policy is enforced",
             password_policy_enforced, "Configure password policy with minimum 12 chars", "SOC2"),
            ("sp-enc", "Encryption at Rest", "All data stores use encryption at rest",
             encryption_at_rest, "Enable encryption at rest for all databases", "HIPAA"),
            ("sp-audit", "Audit Logging", "Comprehensive audit logging is enabled",
             audit_logging, "Enable audit logging for all security events", "SOC2"),
            ("sp-ip", "IP Allowlisting", "IP allowlisting is configured for admin access",
             ip_allowlisting, "Configure IP allowlisting for admin endpoints", "SOC2"),
            ("sp-sess", "Session Timeout", "Session timeout is properly configured",
             session_timeout_configured, "Configure session timeout to 30 minutes or less", "GDPR"),
        ]
        for check_id, name, desc, passing, remediation, framework in checks:
            self.add_check("Security Posture", ComplianceCheck(
                check_id=check_id, name=name, description=desc,
                status=ComplianceStatus.COMPLIANT if passing else ComplianceStatus.NON_COMPLIANT,
                remediation="" if passing else remediation, framework=framework,
            ))
        return self.generate(ReportType.SECURITY_POSTURE)
