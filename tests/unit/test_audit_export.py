"""Tests for audit log export (401)."""
from zuultimate.enterprise.audit_export import AuditExportService

class TestAuditExport:
    def setup_method(self):
        self.svc = AuditExportService()
        self.events = [
            {"timestamp": "2026-01-01T00:00:00Z", "actor": "user1", "action": "login",
             "resource": "auth", "ip": "192.168.1.100", "result": "success"},
            {"timestamp": "2026-01-01T00:01:00Z", "actor": "user2", "action": "read",
             "resource": "vault", "ip": "10.0.0.50", "result": "success"},
        ]

    def test_export_soc2(self):
        export = self.svc.export_logs(self.events, "soc2", "t1")
        assert export["format"] == "soc2"
        assert export["event_count"] == 2

    def test_export_gdpr_anonymizes_ip(self):
        export = self.svc.export_logs(self.events, "gdpr")
        assert export["events"][0]["ip"].endswith(".0.0")

    def test_export_to_csv(self):
        csv = self.svc.export_to_csv(self.events, "soc2")
        lines = csv.strip().split("\n")
        assert len(lines) == 3

    def test_export_to_json(self):
        j = self.svc.export_to_json(self.events, "soc2", "t1")
        assert "soc2" in j

    def test_export_history(self):
        self.svc.export_logs(self.events, "soc2", "t1")
        self.svc.export_logs(self.events, "gdpr", "t1")
        history = self.svc.get_export_history("t1")
        assert len(history) == 2
