"""Unit tests for environment variable validation at startup (item 922)."""

import pytest

from zuultimate.compliance.env_validator import (
    EnvValidationReport,
    EnvValidator,
    EnvVarRule,
    EnvVarType,
    ValidationSeverity,
    create_zuul_validator,
)


class TestEnvValidator:
    @pytest.fixture
    def validator(self):
        return EnvValidator()

    def test_required_var_missing(self, validator):
        validator.add_rule(EnvVarRule(name="MY_VAR", required=True))
        report = validator.validate({})
        assert not report.is_valid
        assert len(report.errors) == 1

    def test_required_var_present(self, validator):
        validator.add_rule(EnvVarRule(name="MY_VAR", required=True))
        report = validator.validate({"MY_VAR": "value"})
        assert report.is_valid

    def test_optional_var_missing_uses_default(self, validator):
        validator.add_rule(EnvVarRule(name="MY_VAR", required=False, default="fallback"))
        report = validator.validate({})
        assert report.is_valid
        assert report.results[0].resolved_value == "fallback"

    def test_integer_validation_pass(self, validator):
        validator.add_rule(EnvVarRule(name="PORT", var_type=EnvVarType.INTEGER))
        report = validator.validate({"PORT": "8080"})
        assert report.is_valid

    def test_integer_validation_fail(self, validator):
        validator.add_rule(EnvVarRule(name="PORT", var_type=EnvVarType.INTEGER))
        report = validator.validate({"PORT": "abc"})
        assert not report.is_valid

    def test_float_validation(self, validator):
        validator.add_rule(EnvVarRule(name="RATE", var_type=EnvVarType.FLOAT))
        assert validator.validate({"RATE": "3.14"}).is_valid
        assert not validator.validate({"RATE": "nope"}).is_valid

    def test_boolean_validation(self, validator):
        validator.add_rule(EnvVarRule(name="DEBUG", var_type=EnvVarType.BOOLEAN))
        for val in ("true", "false", "1", "0", "yes", "no"):
            assert validator.validate({"DEBUG": val}).is_valid
        assert not validator.validate({"DEBUG": "maybe"}).is_valid

    def test_url_validation(self, validator):
        validator.add_rule(EnvVarRule(name="API_URL", var_type=EnvVarType.URL))
        assert validator.validate({"API_URL": "https://example.com"}).is_valid
        assert not validator.validate({"API_URL": "not-a-url"}).is_valid

    def test_email_validation(self, validator):
        validator.add_rule(EnvVarRule(name="ADMIN_EMAIL", var_type=EnvVarType.EMAIL))
        assert validator.validate({"ADMIN_EMAIL": "admin@example.com"}).is_valid
        assert not validator.validate({"ADMIN_EMAIL": "bad"}).is_valid

    def test_min_length(self, validator):
        validator.add_rule(EnvVarRule(name="KEY", min_length=16))
        assert not validator.validate({"KEY": "short"}).is_valid
        assert validator.validate({"KEY": "a" * 16}).is_valid

    def test_regex_validation(self, validator):
        validator.add_rule(EnvVarRule(name="CODE", regex=r"^[A-Z]{3}-\d{3}$"))
        assert validator.validate({"CODE": "ABC-123"}).is_valid
        assert not validator.validate({"CODE": "abc-123"}).is_valid

    def test_custom_validator(self, validator):
        validator.add_rule(EnvVarRule(
            name="EVEN", validator=lambda v: int(v) % 2 == 0,
        ))
        assert validator.validate({"EVEN": "4"}).is_valid
        assert not validator.validate({"EVEN": "3"}).is_valid

    def test_custom_validator_exception(self, validator):
        validator.add_rule(EnvVarRule(
            name="BAD", validator=lambda v: 1 / 0,
        ))
        report = validator.validate({"BAD": "x"})
        assert not report.is_valid

    def test_secret_type_hides_value(self, validator):
        validator.add_rule(EnvVarRule(name="SECRET", var_type=EnvVarType.SECRET))
        report = validator.validate({"SECRET": "supersecret"})
        assert report.results[0].resolved_value == "[set]"

    def test_secret_default_hidden(self, validator):
        validator.add_rule(EnvVarRule(name="SECRET", var_type=EnvVarType.SECRET,
                                     required=False, default="default-secret"))
        report = validator.validate({})
        assert report.results[0].resolved_value == "[default]"

    def test_warning_severity(self, validator):
        validator.add_rule(EnvVarRule(name="OPT", required=True,
                                     severity=ValidationSeverity.WARNING))
        report = validator.validate({})
        # Warnings don't make the report invalid
        assert report.is_valid
        assert len(report.warnings) == 1

    def test_add_rules_batch(self, validator):
        validator.add_rules([
            EnvVarRule(name="A"), EnvVarRule(name="B"),
        ])
        report = validator.validate({})
        assert len(report.errors) == 2

    def test_to_dict(self, validator):
        validator.add_rule(EnvVarRule(name="X"))
        report = validator.validate({"X": "v"})
        d = report.to_dict()
        assert d["valid"]
        assert d["error_count"] == 0
        assert d["total_checked"] == 1

    def test_report_timestamp(self, validator):
        validator.add_rule(EnvVarRule(name="X", required=False, default=""))
        report = validator.validate({})
        assert report.timestamp > 0


class TestZuulValidator:
    def test_zuul_validator_with_required_key(self):
        v = create_zuul_validator()
        report = v.validate({"ZUUL_SECRET_KEY": "a" * 32})
        assert report.is_valid

    def test_zuul_validator_missing_secret(self):
        v = create_zuul_validator()
        report = v.validate({})
        assert not report.is_valid
        error_names = [e.var_name for e in report.errors]
        assert "ZUUL_SECRET_KEY" in error_names

    def test_zuul_validator_short_secret(self):
        v = create_zuul_validator()
        report = v.validate({"ZUUL_SECRET_KEY": "short"})
        assert not report.is_valid
