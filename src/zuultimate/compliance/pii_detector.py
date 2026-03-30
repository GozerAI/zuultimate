"""Automated PII detection and masking engine.

Scans text and structured data for personally identifiable information (email,
phone, SSN, credit card, IP addresses, etc.) and returns masked versions.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PIIType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    IBAN = "iban"
    CUSTOM = "custom"


@dataclass
class PIIMatch:
    """A detected PII occurrence."""
    pii_type: PIIType
    start: int
    end: int
    original: str
    masked: str


@dataclass
class PIIPattern:
    """A compiled regex pattern for a PII type."""
    pii_type: PIIType
    pattern: re.Pattern[str]
    mask_char: str = "*"
    preserve_prefix: int = 0
    preserve_suffix: int = 0


_BUILTIN_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        pii_type=PIIType.EMAIL,
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        preserve_prefix=1,
        preserve_suffix=0,
    ),
    PIIPattern(
        pii_type=PIIType.PHONE,
        pattern=re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        preserve_suffix=4,
    ),
    PIIPattern(
        pii_type=PIIType.SSN,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        preserve_suffix=4,
    ),
    PIIPattern(
        pii_type=PIIType.CREDIT_CARD,
        pattern=re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        preserve_suffix=4,
    ),
    PIIPattern(
        pii_type=PIIType.IP_ADDRESS,
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        preserve_prefix=0,
        preserve_suffix=0,
    ),
    PIIPattern(
        pii_type=PIIType.DATE_OF_BIRTH,
        pattern=re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"),
    ),
]


def _mask_value(value: str, mask_char: str, preserve_prefix: int, preserve_suffix: int) -> str:
    length = len(value)
    if length <= preserve_prefix + preserve_suffix:
        return mask_char * length
    prefix = value[:preserve_prefix]
    suffix = value[length - preserve_suffix:] if preserve_suffix else ""
    middle_len = length - preserve_prefix - preserve_suffix
    return f"{prefix}{mask_char * middle_len}{suffix}"


@dataclass
class PIIDetector:
    """Detects and masks PII in text and structured data."""

    patterns: list[PIIPattern] = field(default_factory=lambda: list(_BUILTIN_PATTERNS))
    custom_patterns: list[PIIPattern] = field(default_factory=list)

    def add_pattern(
        self,
        pii_type: PIIType,
        regex: str,
        mask_char: str = "*",
        preserve_prefix: int = 0,
        preserve_suffix: int = 0,
    ) -> None:
        self.custom_patterns.append(
            PIIPattern(
                pii_type=pii_type,
                pattern=re.compile(regex),
                mask_char=mask_char,
                preserve_prefix=preserve_prefix,
                preserve_suffix=preserve_suffix,
            )
        )

    @property
    def _all_patterns(self) -> list[PIIPattern]:
        return self.patterns + self.custom_patterns

    def scan(self, text: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []
        for pat in self._all_patterns:
            for m in pat.pattern.finditer(text):
                original = m.group(0)
                masked = _mask_value(
                    original, pat.mask_char, pat.preserve_prefix, pat.preserve_suffix,
                )
                matches.append(PIIMatch(
                    pii_type=pat.pii_type, start=m.start(), end=m.end(),
                    original=original, masked=masked,
                ))
        matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        deduped: list[PIIMatch] = []
        last_end = -1
        for match in matches:
            if match.start >= last_end:
                deduped.append(match)
                last_end = match.end
        return deduped

    def mask(self, text: str) -> str:
        matches = self.scan(text)
        if not matches:
            return text
        parts: list[str] = []
        prev_end = 0
        for m in matches:
            parts.append(text[prev_end:m.start])
            parts.append(m.masked)
            prev_end = m.end
        parts.append(text[prev_end:])
        return "".join(parts)

    def mask_dict(self, data: dict[str, Any], fields: list[str] | None = None) -> dict[str, Any]:
        result = dict(data)
        target_fields = fields or [k for k, v in data.items() if isinstance(v, str)]
        for key in target_fields:
            if key in result and isinstance(result[key], str):
                result[key] = self.mask(result[key])
        return result

    def has_pii(self, text: str) -> bool:
        return len(self.scan(text)) > 0

    def get_pii_types(self, text: str) -> set[PIIType]:
        return {m.pii_type for m in self.scan(text)}
