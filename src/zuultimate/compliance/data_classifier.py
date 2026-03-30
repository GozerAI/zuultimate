"""Data classification and labeling engine.

Classifies data fields by sensitivity level and applies appropriate
handling labels (public, internal, confidential, restricted).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SensitivityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class DataCategory(str, Enum):
    PII = "pii"
    FINANCIAL = "financial"
    HEALTH = "health"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"
    BUSINESS = "business"
    PUBLIC_INFO = "public_info"


@dataclass
class ClassificationRule:
    """Maps field name patterns to sensitivity levels."""
    field_pattern: str  # substring match against field name (lowercased)
    sensitivity: SensitivityLevel
    category: DataCategory
    requires_encryption: bool = False
    requires_masking: bool = False
    retention_days: int = 365


@dataclass
class ClassificationResult:
    field_name: str
    sensitivity: SensitivityLevel
    category: DataCategory
    requires_encryption: bool
    requires_masking: bool
    retention_days: int
    matched_rule: str


_DEFAULT_RULES: list[ClassificationRule] = [
    # Authentication
    ClassificationRule("password", SensitivityLevel.RESTRICTED, DataCategory.AUTHENTICATION,
                       requires_encryption=True, requires_masking=True, retention_days=0),
    ClassificationRule("secret", SensitivityLevel.RESTRICTED, DataCategory.AUTHENTICATION,
                       requires_encryption=True, requires_masking=True, retention_days=0),
    ClassificationRule("token", SensitivityLevel.RESTRICTED, DataCategory.AUTHENTICATION,
                       requires_encryption=True, requires_masking=True, retention_days=90),
    ClassificationRule("api_key", SensitivityLevel.RESTRICTED, DataCategory.AUTHENTICATION,
                       requires_encryption=True, requires_masking=True, retention_days=90),
    ClassificationRule("mfa", SensitivityLevel.RESTRICTED, DataCategory.AUTHENTICATION,
                       requires_encryption=True, retention_days=90),
    # PII
    ClassificationRule("email", SensitivityLevel.CONFIDENTIAL, DataCategory.PII,
                       requires_masking=True, retention_days=365),
    ClassificationRule("phone", SensitivityLevel.CONFIDENTIAL, DataCategory.PII,
                       requires_masking=True, retention_days=365),
    ClassificationRule("ssn", SensitivityLevel.RESTRICTED, DataCategory.PII,
                       requires_encryption=True, requires_masking=True, retention_days=365),
    ClassificationRule("address", SensitivityLevel.CONFIDENTIAL, DataCategory.PII,
                       retention_days=365),
    ClassificationRule("date_of_birth", SensitivityLevel.CONFIDENTIAL, DataCategory.PII,
                       requires_masking=True, retention_days=365),
    ClassificationRule("ip_address", SensitivityLevel.CONFIDENTIAL, DataCategory.PII,
                       requires_masking=True, retention_days=90),
    ClassificationRule("user_agent", SensitivityLevel.INTERNAL, DataCategory.PII,
                       retention_days=90),
    # Financial
    ClassificationRule("credit_card", SensitivityLevel.RESTRICTED, DataCategory.FINANCIAL,
                       requires_encryption=True, requires_masking=True, retention_days=365),
    ClassificationRule("bank_account", SensitivityLevel.RESTRICTED, DataCategory.FINANCIAL,
                       requires_encryption=True, requires_masking=True, retention_days=365),
    ClassificationRule("stripe", SensitivityLevel.CONFIDENTIAL, DataCategory.FINANCIAL,
                       retention_days=365),
    # Health
    ClassificationRule("diagnosis", SensitivityLevel.RESTRICTED, DataCategory.HEALTH,
                       requires_encryption=True, retention_days=730),
    ClassificationRule("medical", SensitivityLevel.RESTRICTED, DataCategory.HEALTH,
                       requires_encryption=True, retention_days=730),
    # System
    ClassificationRule("tenant_id", SensitivityLevel.INTERNAL, DataCategory.SYSTEM,
                       retention_days=0),
    ClassificationRule("created_at", SensitivityLevel.INTERNAL, DataCategory.SYSTEM,
                       retention_days=0),
    ClassificationRule("updated_at", SensitivityLevel.INTERNAL, DataCategory.SYSTEM,
                       retention_days=0),
    # Business
    ClassificationRule("plan", SensitivityLevel.INTERNAL, DataCategory.BUSINESS,
                       retention_days=365),
    ClassificationRule("slug", SensitivityLevel.PUBLIC, DataCategory.PUBLIC_INFO,
                       retention_days=0),
    ClassificationRule("name", SensitivityLevel.INTERNAL, DataCategory.BUSINESS,
                       retention_days=365),
]


class DataClassifier:
    """Classifies data fields by sensitivity level.

    Usage::

        classifier = DataClassifier()
        result = classifier.classify_field("user_email")
        assert result.sensitivity == SensitivityLevel.CONFIDENTIAL
    """

    def __init__(self, rules: list[ClassificationRule] | None = None) -> None:
        self._rules = rules if rules is not None else list(_DEFAULT_RULES)

    def add_rule(self, rule: ClassificationRule) -> None:
        self._rules.insert(0, rule)  # custom rules take precedence

    def classify_field(self, field_name: str) -> ClassificationResult:
        lower = field_name.lower()
        for rule in self._rules:
            if rule.field_pattern in lower:
                return ClassificationResult(
                    field_name=field_name,
                    sensitivity=rule.sensitivity,
                    category=rule.category,
                    requires_encryption=rule.requires_encryption,
                    requires_masking=rule.requires_masking,
                    retention_days=rule.retention_days,
                    matched_rule=rule.field_pattern,
                )
        return ClassificationResult(
            field_name=field_name,
            sensitivity=SensitivityLevel.INTERNAL,
            category=DataCategory.SYSTEM,
            requires_encryption=False,
            requires_masking=False,
            retention_days=365,
            matched_rule="default",
        )

    def classify_schema(self, field_names: list[str]) -> dict[str, ClassificationResult]:
        return {f: self.classify_field(f) for f in field_names}

    def get_fields_requiring_encryption(self, field_names: list[str]) -> list[str]:
        return [f for f in field_names if self.classify_field(f).requires_encryption]

    def get_fields_requiring_masking(self, field_names: list[str]) -> list[str]:
        return [f for f in field_names if self.classify_field(f).requires_masking]

    def get_restricted_fields(self, field_names: list[str]) -> list[str]:
        return [f for f in field_names
                if self.classify_field(f).sensitivity == SensitivityLevel.RESTRICTED]

    def validate_retention(self, field_name: str, actual_days: int) -> bool:
        """Return True if the actual retention meets the field's policy."""
        result = self.classify_field(field_name)
        if result.retention_days == 0:
            return True  # no retention limit
        return actual_days <= result.retention_days
