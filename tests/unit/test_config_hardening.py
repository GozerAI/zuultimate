"""Hardening tests for ZuulSettings — defaults, env prefix, production validation."""

from __future__ import annotations

import pytest

from zuultimate.common.config import ZuulSettings, _INSECURE_DEFAULT_KEY


# ---------------------------------------------------------------------------
# 1. All settings have defaults (no env vars required)
# ---------------------------------------------------------------------------


def test_all_settings_have_defaults():
    settings = ZuulSettings()
    assert settings.environment == "development"
    assert settings.secret_key == _INSECURE_DEFAULT_KEY
    assert settings.identity_db_url
    assert settings.credential_db_url
    assert settings.session_db_url
    assert settings.transaction_db_url
    assert settings.audit_db_url
    assert settings.crm_db_url


# ---------------------------------------------------------------------------
# 2. ZUUL_ env prefix
# ---------------------------------------------------------------------------


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("ZUUL_ENVIRONMENT", "staging")
    monkeypatch.setenv("ZUUL_SECRET_KEY", "my-secret")
    monkeypatch.setenv("ZUUL_REGION", "eu")
    settings = ZuulSettings()
    assert settings.environment == "staging"
    assert settings.secret_key == "my-secret"
    assert settings.region == "eu"


# ---------------------------------------------------------------------------
# 3. Default identity_db_url is SQLite
# ---------------------------------------------------------------------------


def test_identity_db_url_default():
    settings = ZuulSettings()
    assert "sqlite" in settings.identity_db_url


# ---------------------------------------------------------------------------
# 4. All six DB URLs can be distinct
# ---------------------------------------------------------------------------


def test_all_six_db_urls_distinct():
    urls = {
        "identity_db_url": "sqlite+aiosqlite:///./data/id.db",
        "credential_db_url": "sqlite+aiosqlite:///./data/cred.db",
        "session_db_url": "sqlite+aiosqlite:///./data/sess.db",
        "transaction_db_url": "sqlite+aiosqlite:///./data/txn.db",
        "audit_db_url": "sqlite+aiosqlite:///./data/aud.db",
        "crm_db_url": "sqlite+aiosqlite:///./data/crm2.db",
    }
    settings = ZuulSettings(**urls)
    actual = [getattr(settings, k) for k in urls]
    assert len(set(actual)) == 6, "All 6 DB URLs should be distinct"


# ---------------------------------------------------------------------------
# 5. Production rejects insecure key
# ---------------------------------------------------------------------------


def test_production_rejects_insecure_key():
    settings = ZuulSettings(environment="production")
    with pytest.raises(RuntimeError, match="ZUUL_SECRET_KEY must be set"):
        settings.validate_for_production()


# ---------------------------------------------------------------------------
# 6. Production accepts secure key (and custom salts)
# ---------------------------------------------------------------------------


def test_production_accepts_secure_key():
    settings = ZuulSettings(
        environment="production",
        secret_key="a-very-secure-key-that-is-not-default",
        vault_salt="custom-vault-salt",
        mfa_salt="custom-mfa-salt",
        password_vault_salt="custom-pw-salt",
    )
    # Should not raise
    settings.validate_for_production()


# ---------------------------------------------------------------------------
# 7. Token expiration defaults
# ---------------------------------------------------------------------------


def test_token_expire_defaults():
    settings = ZuulSettings()
    assert settings.access_token_expire_minutes == 60
    assert settings.refresh_token_expire_days == 7


# ---------------------------------------------------------------------------
# 8. Rate limit defaults
# ---------------------------------------------------------------------------


def test_rate_limit_defaults():
    settings = ZuulSettings()
    assert settings.login_rate_limit == 10
    assert settings.login_rate_window == 300


# ---------------------------------------------------------------------------
# 9. CORS defaults
# ---------------------------------------------------------------------------


def test_cors_defaults():
    settings = ZuulSettings()
    assert "http://localhost:3000" in settings.cors_origins
    assert "http://localhost:8000" in settings.cors_origins


# ---------------------------------------------------------------------------
# 10. Region / sovereignty defaults
# ---------------------------------------------------------------------------


def test_region_default():
    settings = ZuulSettings()
    assert settings.region == "us"
    assert settings.sovereignty_ring == "us"
