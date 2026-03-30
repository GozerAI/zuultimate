"""Unit tests for data classification and labeling (item 897)."""

import pytest

from zuultimate.compliance.data_classifier import (
    ClassificationResult,
    ClassificationRule,
    DataCategory,
    DataClassifier,
    SensitivityLevel,
)


class TestDataClassifier:
    @pytest.fixture
    def classifier(self):
        return DataClassifier()

    def test_email_classified_confidential(self, classifier):
        r = classifier.classify_field("user_email")
        assert r.sensitivity == SensitivityLevel.CONFIDENTIAL
        assert r.category == DataCategory.PII
        assert r.requires_masking

    def test_password_classified_restricted(self, classifier):
        r = classifier.classify_field("hashed_password")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.category == DataCategory.AUTHENTICATION
        assert r.requires_encryption
        assert r.requires_masking

    def test_ssn_classified_restricted(self, classifier):
        r = classifier.classify_field("ssn")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.category == DataCategory.PII

    def test_credit_card_classified_restricted(self, classifier):
        r = classifier.classify_field("credit_card_number")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.category == DataCategory.FINANCIAL

    def test_tenant_id_internal(self, classifier):
        r = classifier.classify_field("tenant_id")
        assert r.sensitivity == SensitivityLevel.INTERNAL
        assert r.category == DataCategory.SYSTEM

    def test_slug_public(self, classifier):
        r = classifier.classify_field("company_slug")
        assert r.sensitivity == SensitivityLevel.PUBLIC

    def test_unknown_field_default(self, classifier):
        r = classifier.classify_field("random_field_xyz")
        assert r.sensitivity == SensitivityLevel.INTERNAL
        assert r.matched_rule == "default"

    def test_classify_schema(self, classifier):
        results = classifier.classify_schema(["email", "password", "slug"])
        assert len(results) == 3
        assert results["email"].sensitivity == SensitivityLevel.CONFIDENTIAL
        assert results["password"].sensitivity == SensitivityLevel.RESTRICTED
        assert results["slug"].sensitivity == SensitivityLevel.PUBLIC

    def test_fields_requiring_encryption(self, classifier):
        fields = ["email", "password", "ssn", "slug", "name"]
        encrypted = classifier.get_fields_requiring_encryption(fields)
        assert "password" in encrypted
        assert "ssn" in encrypted
        assert "email" not in encrypted

    def test_fields_requiring_masking(self, classifier):
        fields = ["email", "password", "slug"]
        masked = classifier.get_fields_requiring_masking(fields)
        assert "email" in masked
        assert "password" in masked
        assert "slug" not in masked

    def test_restricted_fields(self, classifier):
        fields = ["password", "email", "ssn", "slug"]
        restricted = classifier.get_restricted_fields(fields)
        assert "password" in restricted
        assert "ssn" in restricted
        assert "email" not in restricted

    def test_validate_retention_within_limit(self, classifier):
        assert classifier.validate_retention("email", 365)

    def test_validate_retention_exceeded(self, classifier):
        assert not classifier.validate_retention("email", 400)

    def test_validate_retention_no_limit(self, classifier):
        # tenant_id has retention_days=0 (no limit)
        assert classifier.validate_retention("tenant_id", 9999)

    def test_custom_rule_takes_precedence(self):
        classifier = DataClassifier()
        classifier.add_rule(ClassificationRule(
            "email", SensitivityLevel.RESTRICTED, DataCategory.PII,
            requires_encryption=True, retention_days=30,
        ))
        r = classifier.classify_field("email")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.requires_encryption

    def test_health_data(self, classifier):
        r = classifier.classify_field("medical_record")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.category == DataCategory.HEALTH
        assert r.requires_encryption

    def test_api_key_restricted(self, classifier):
        r = classifier.classify_field("api_key_hash")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
        assert r.category == DataCategory.AUTHENTICATION

    def test_token_restricted(self, classifier):
        r = classifier.classify_field("refresh_token")
        assert r.sensitivity == SensitivityLevel.RESTRICTED
