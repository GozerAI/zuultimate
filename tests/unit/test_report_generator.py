"""Unit tests for automated compliance report generation (item 893)."""

import pytest

from zuultimate.compliance.report_generator import (
    ComplianceCheck,
    ComplianceReport,
    ComplianceReportGenerator,
    ComplianceSection,
    ComplianceStatus,
    ReportType,
)


class TestComplianceSection:
    def test_empty_section_compliance_rate(self):
        s = ComplianceSection(title="empty")
        assert s.compliance_rate == 1.0
        assert s.pass_count == 0
        assert s.fail_count == 0

    def test_all_compliant(self):
        s = ComplianceSection(title="test", checks=[
            ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT),
            ComplianceCheck("c2", "C2", "D2", ComplianceStatus.COMPLIANT),
        ])
        assert s.compliance_rate == 1.0
        assert s.pass_count == 2
        assert s.fail_count == 0

    def test_mixed_compliance(self):
        s = ComplianceSection(title="test", checks=[
            ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT),
            ComplianceCheck("c2", "C2", "D2", ComplianceStatus.NON_COMPLIANT),
        ])
        assert s.compliance_rate == 0.5
        assert s.pass_count == 1
        assert s.fail_count == 1


class TestComplianceReport:
    def test_not_assessed_when_empty(self):
        report = ComplianceReport(
            report_id="r1", report_type=ReportType.FULL_AUDIT,
            generated_at="2026-01-01T00:00:00Z", tenant_id="t1",
        )
        assert report.overall_status == ComplianceStatus.NOT_ASSESSED
        assert report.total_checks == 0
        assert report.overall_compliance_rate == 1.0

    def test_compliant_report(self):
        section = ComplianceSection(title="test", checks=[
            ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT),
        ])
        report = ComplianceReport(
            report_id="r1", report_type=ReportType.FULL_AUDIT,
            generated_at="2026-01-01T00:00:00Z", tenant_id="t1",
            sections=[section],
        )
        assert report.overall_status == ComplianceStatus.COMPLIANT
        assert report.overall_compliance_rate == 1.0

    def test_non_compliant_report(self):
        section = ComplianceSection(title="test", checks=[
            ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT),
            ComplianceCheck("c2", "C2", "D2", ComplianceStatus.NON_COMPLIANT),
        ])
        report = ComplianceReport(
            report_id="r1", report_type=ReportType.FULL_AUDIT,
            generated_at="2026-01-01T00:00:00Z", tenant_id="t1",
            sections=[section],
        )
        assert report.overall_status == ComplianceStatus.NON_COMPLIANT

    def test_partially_compliant(self):
        section = ComplianceSection(title="test", checks=[
            ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT),
            ComplianceCheck("c2", "C2", "D2", ComplianceStatus.PARTIALLY_COMPLIANT),
        ])
        report = ComplianceReport(
            report_id="r1", report_type=ReportType.FULL_AUDIT,
            generated_at="2026-01-01T00:00:00Z", tenant_id="t1",
            sections=[section],
        )
        assert report.overall_status == ComplianceStatus.PARTIALLY_COMPLIANT

    def test_to_dict(self):
        section = ComplianceSection(title="Security", checks=[
            ComplianceCheck("c1", "MFA", "MFA enabled", ComplianceStatus.COMPLIANT, framework="SOC2"),
        ])
        report = ComplianceReport(
            report_id="r1", report_type=ReportType.SECURITY_POSTURE,
            generated_at="2026-01-01T00:00:00Z", tenant_id="t1",
            sections=[section], metadata={"version": "1"},
        )
        d = report.to_dict()
        assert d["report_id"] == "r1"
        assert d["report_type"] == "security_posture"
        assert d["overall_status"] == "compliant"
        assert d["total_checks"] == 1
        assert len(d["sections"]) == 1
        assert d["sections"][0]["checks"][0]["framework"] == "SOC2"
        assert d["metadata"] == {"version": "1"}


class TestComplianceReportGenerator:
    @pytest.fixture
    def gen(self):
        return ComplianceReportGenerator(tenant_id="t1")

    def test_add_section(self, gen):
        s = gen.add_section("Auth")
        assert s.title == "Auth"
        # Idempotent
        s2 = gen.add_section("Auth")
        assert s is s2

    def test_add_check_creates_section(self, gen):
        gen.add_check("Data", ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT))
        report = gen.generate()
        assert report.total_checks == 1
        assert report.sections[0].title == "Data"

    def test_generate_increments_counter(self, gen):
        r1 = gen.generate()
        r2 = gen.generate()
        assert r1.report_id != r2.report_id

    def test_generate_with_metadata(self, gen):
        report = gen.generate(metadata={"env": "test"})
        assert report.metadata == {"env": "test"}

    def test_generate_report_type(self, gen):
        report = gen.generate(report_type=ReportType.PII_EXPOSURE)
        assert report.report_type == ReportType.PII_EXPOSURE

    def test_clear(self, gen):
        gen.add_check("S", ComplianceCheck("c1", "C1", "D1", ComplianceStatus.COMPLIANT))
        gen.clear()
        report = gen.generate()
        assert report.total_checks == 0

    def test_security_posture_checks_all_passing(self, gen):
        report = gen.run_security_posture_checks(
            mfa_enabled=True, password_policy_enforced=True,
            encryption_at_rest=True, audit_logging=True,
            ip_allowlisting=True, session_timeout_configured=True,
        )
        assert report.overall_status == ComplianceStatus.COMPLIANT
        assert report.total_checks == 6

    def test_security_posture_checks_partial(self, gen):
        report = gen.run_security_posture_checks(
            mfa_enabled=True, password_policy_enforced=False,
            encryption_at_rest=True, audit_logging=False,
        )
        assert report.overall_status == ComplianceStatus.NON_COMPLIANT
        failing = [c for s in report.sections for c in s.checks
                    if c.status == ComplianceStatus.NON_COMPLIANT]
        assert len(failing) >= 2
        # Failing checks have remediation text
        for c in failing:
            assert c.remediation != ""
