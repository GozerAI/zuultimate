"""Tests for zuultimate.common.config -- ZuulSettings pydantic-settings model."""

from __future__ import annotations

import os

from zuultimate.common.config import ZuulSettings


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


def test_default_settings():
    settings = ZuulSettings()
    assert settings.environment == "development"


def test_default_db_urls():
    settings = ZuulSettings()
    assert "sqlite" in settings.identity_db_url


def test_default_secret_key():
    settings = ZuulSettings()
    assert settings.secret_key  # non-empty


def test_max_audit_events_default():
    settings = ZuulSettings()
    assert settings.max_audit_events == 10000


# ---------------------------------------------------------------------------
# Environment variable override
# ---------------------------------------------------------------------------


def test_env_override(monkeypatch):
    monkeypatch.setenv("ZUUL_ENVIRONMENT", "production")
    settings = ZuulSettings()
    assert settings.environment == "production"
