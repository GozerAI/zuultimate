"""Environment variable validation at startup.

Validates that all required environment variables are present and correctly
formatted before the application starts, preventing runtime failures.
"""

from __future__ import annotations

import os
import re
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class EnvVarType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    URL = "url"
    EMAIL = "email"
    SECRET = "secret"


class ValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class EnvVarRule:
    name: str
    var_type: EnvVarType = EnvVarType.STRING
    required: bool = True
    default: str | None = None
    min_length: int = 0
    regex: str | None = None
    description: str = ""
    severity: ValidationSeverity = ValidationSeverity.ERROR
    validator: Callable[[str], bool] | None = None


@dataclass
class EnvValidationResult:
    var_name: str
    valid: bool
    value_present: bool
    message: str = ""
    severity: ValidationSeverity = ValidationSeverity.ERROR
    resolved_value: str | None = None


@dataclass
class EnvValidationReport:
    results: list[EnvValidationResult] = field(default_factory=list)
    timestamp: float = 0.0

    @property
    def is_valid(self) -> bool:
        return all(
            r.valid for r in self.results
            if r.severity == ValidationSeverity.ERROR
        )

    @property
    def errors(self) -> list[EnvValidationResult]:
        return [r for r in self.results if not r.valid and r.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[EnvValidationResult]:
        return [r for r in self.results if not r.valid and r.severity == ValidationSeverity.WARNING]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "total_checked": len(self.results),
            "results": [
                {
                    "var_name": r.var_name, "valid": r.valid,
                    "present": r.value_present, "message": r.message,
                    "severity": r.severity.value,
                }
                for r in self.results
            ],
        }


_URL_PATTERN = re.compile(r"^https?://[^\s]+$")
_EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$")


class EnvValidator:
    """Validates environment variables against declared rules."""

    def __init__(self) -> None:
        self._rules: list[EnvVarRule] = []

    def add_rule(self, rule: EnvVarRule) -> None:
        self._rules.append(rule)

    def add_rules(self, rules: list[EnvVarRule]) -> None:
        self._rules.extend(rules)

    def validate(self, env: dict[str, str] | None = None) -> EnvValidationReport:
        source = env if env is not None else dict(os.environ)
        results: list[EnvValidationResult] = []

        for rule in self._rules:
            value = source.get(rule.name)
            present = value is not None

            if not present:
                if rule.required and rule.default is None:
                    results.append(EnvValidationResult(
                        var_name=rule.name, valid=False, value_present=False,
                        message=f"Required variable {rule.name} is not set",
                        severity=rule.severity,
                    ))
                else:
                    resolved = rule.default or ""
                    results.append(EnvValidationResult(
                        var_name=rule.name, valid=True, value_present=False,
                        message=f"Using default value for {rule.name}",
                        severity=ValidationSeverity.INFO,
                        resolved_value="[default]" if rule.var_type == EnvVarType.SECRET else resolved,
                    ))
                continue

            valid = True
            message = ""

            if rule.var_type == EnvVarType.INTEGER:
                try:
                    int(value)
                except ValueError:
                    valid = False
                    message = f"{rule.name} must be an integer"

            elif rule.var_type == EnvVarType.FLOAT:
                try:
                    float(value)
                except ValueError:
                    valid = False
                    message = f"{rule.name} must be a float"

            elif rule.var_type == EnvVarType.BOOLEAN:
                if value.lower() not in ("true", "false", "1", "0", "yes", "no"):
                    valid = False
                    message = f"{rule.name} must be a boolean value"

            elif rule.var_type == EnvVarType.URL:
                if not _URL_PATTERN.match(value):
                    valid = False
                    message = f"{rule.name} must be a valid URL"

            elif rule.var_type == EnvVarType.EMAIL:
                if not _EMAIL_PATTERN.match(value):
                    valid = False
                    message = f"{rule.name} must be a valid email"

            if valid and rule.min_length > 0 and len(value) < rule.min_length:
                valid = False
                message = f"{rule.name} must be at least {rule.min_length} characters"

            if valid and rule.regex:
                if not re.match(rule.regex, value):
                    valid = False
                    message = f"{rule.name} does not match required pattern"

            if valid and rule.validator:
                try:
                    if not rule.validator(value):
                        valid = False
                        message = f"{rule.name} failed custom validation"
                except Exception as exc:
                    valid = False
                    message = f"{rule.name} validator error: {exc}"

            display_value = "[set]" if rule.var_type == EnvVarType.SECRET else value
            results.append(EnvValidationResult(
                var_name=rule.name, valid=valid, value_present=True,
                message=message if not valid else "OK",
                severity=rule.severity, resolved_value=display_value,
            ))

        return EnvValidationReport(results=results, timestamp=_time.time())


def create_zuul_validator() -> EnvValidator:
    v = EnvValidator()
    v.add_rules([
        EnvVarRule(name="ZUUL_SECRET_KEY", var_type=EnvVarType.SECRET,
                   min_length=16, description="Application secret key"),
        EnvVarRule(name="ZUUL_ENVIRONMENT", var_type=EnvVarType.STRING,
                   required=False, default="development",
                   description="Deployment environment"),
        EnvVarRule(name="ZUUL_REDIS_URL", var_type=EnvVarType.URL,
                   required=False, default="redis://localhost:6379/0",
                   severity=ValidationSeverity.WARNING,
                   description="Redis connection URL"),
        EnvVarRule(name="ZUUL_CORS_ORIGINS", var_type=EnvVarType.STRING,
                   required=False, default="http://localhost:3000",
                   description="CORS allowed origins"),
        EnvVarRule(name="ZUUL_SERVICE_TOKEN", var_type=EnvVarType.SECRET,
                   required=False, default="",
                   severity=ValidationSeverity.WARNING,
                   description="Service-to-service auth token"),
    ])
    return v
