"""PoP service configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class PopSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POP_")

    pop_id: str = "pop-local-01"
    pop_name: str = "Local PoP"
    region: str = "us"

    # Zuultimate upstream
    zuultimate_url: str = "http://localhost:8000"

    # mTLS
    ca_cert_path: str = ""
    crl_url: str = ""
    crl_refresh_seconds: int = 900  # 15 minutes

    # PoP signing key (PEM)
    private_key_path: str = ""

    # Server
    host: str = "0.0.0.0"
    port: int = 8001
