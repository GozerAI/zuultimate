"""Unit tests for automated PII detection and masking (item 891)."""

import pytest

from zuultimate.compliance.pii_detector import (
    PIIDetector,
    PIIMatch,
    PIIPattern,
    PIIType,
    _mask_value,
)


class TestMaskValue:
    def test_full_mask(self):
        assert _mask_value("hello", "*", 0, 0) == "*****"

    def test_preserve_prefix(self):
        assert _mask_value("hello", "*", 2, 0) == "he***"

    def test_preserve_suffix(self):
        assert _mask_value("hello", "*", 0, 2) == "***lo"

    def test_preserve_both(self):
        assert _mask_value("abcdef", "*", 1, 1) == "a****f"

    def test_short_value_all_masked(self):
        assert _mask_value("ab", "*", 3, 3) == "**"

    def test_custom_mask_char(self):
        assert _mask_value("secret", "X", 0, 0) == "XXXXXX"


class TestPIIDetector:
    @pytest.fixture
    def detector(self):
        return PIIDetector()

    def test_detect_email(self, detector):
        matches = detector.scan("Contact us at john.doe@example.com today")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.EMAIL
        assert matches[0].original == "john.doe@example.com"

    def test_mask_email(self, detector):
        result = detector.mask("Email: john.doe@example.com")
        assert "john.doe@example.com" not in result
        assert result.startswith("Email: j")

    def test_detect_phone(self, detector):
        matches = detector.scan("Call 555-123-4567 for info")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.PHONE

    def test_mask_phone_preserves_suffix(self, detector):
        result = detector.mask("Phone: 555-123-4567")
        assert result.endswith("4567")
        assert "555-123-4567" not in result

    def test_detect_ssn(self, detector):
        matches = detector.scan("SSN: 123-45-6789")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.SSN

    def test_mask_ssn_preserves_last_four(self, detector):
        result = detector.mask("SSN: 123-45-6789")
        assert result.endswith("6789")

    def test_detect_credit_card(self, detector):
        matches = detector.scan("Card: 4111-1111-1111-1111")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.CREDIT_CARD

    def test_detect_ip_address(self, detector):
        matches = detector.scan("IP: 192.168.1.100")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.IP_ADDRESS

    def test_detect_date_of_birth(self, detector):
        matches = detector.scan("DOB: 1990-01-15")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.DATE_OF_BIRTH

    def test_no_pii(self, detector):
        assert not detector.has_pii("This is a clean text with no PII")

    def test_has_pii(self, detector):
        assert detector.has_pii("Email me at test@example.com")

    def test_get_pii_types(self, detector):
        text = "Email: a@b.com, SSN: 123-45-6789"
        types = detector.get_pii_types(text)
        assert PIIType.EMAIL in types
        assert PIIType.SSN in types

    def test_multiple_pii_in_text(self, detector):
        text = "User a@b.com called from 555-123-4567 with SSN 111-22-3333"
        matches = detector.scan(text)
        assert len(matches) >= 3

    def test_mask_dict(self, detector):
        data = {"name": "John", "email": "john@example.com", "age": "30"}
        result = detector.mask_dict(data)
        assert "john@example.com" not in result["email"]
        assert result["name"] == "John"
        assert result["age"] == "30"

    def test_mask_dict_specific_fields(self, detector):
        data = {"email": "a@b.com", "note": "contact a@b.com"}
        result = detector.mask_dict(data, fields=["email"])
        assert "a@b.com" not in result["email"]
        assert result["note"] == "contact a@b.com"

    def test_mask_preserves_non_pii(self, detector):
        text = "Hello world, no PII here."
        assert detector.mask(text) == text

    def test_custom_pattern(self):
        detector = PIIDetector()
        detector.add_pattern(PIIType.CUSTOM, r"ACCT-\d{8}", mask_char="#", preserve_prefix=5)
        matches = detector.scan("Account: ACCT-12345678")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.CUSTOM
        masked = detector.mask("Account: ACCT-12345678")
        assert masked.startswith("Account: ACCT-")

    def test_overlapping_matches_deduplicated(self, detector):
        text = "Server at 192.168.1.1"
        matches = detector.scan(text)
        starts = [m.start for m in matches]
        assert len(starts) == len(set(starts))

    def test_empty_text(self, detector):
        assert detector.scan("") == []
        assert detector.mask("") == ""
        assert not detector.has_pii("")
