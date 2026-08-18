"""Owns runtime configuration. Everything comes from the environment, nothing from files.

Secrets are never read from the repo; `.env.example` documents the variable names
with placeholder values only.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings, loaded once at startup."""

    model_config = SettingsConfigDict(env_prefix="REACHSET_", extra="ignore")

    database_url: str = "postgresql+asyncpg://reachset:reachset@localhost:5442/reachset"
    redis_url: str = "redis://localhost:6390/0"
    vault_addr: str = "http://localhost:8220"
    # Dev-server token. Real deployments authenticate via an auth method instead.
    vault_token: str = ""
    log_level: str = "INFO"
    reach_depth_cap: int = 8


def load_settings() -> Settings:
    """Read settings from the environment. Kept as a function so tests can override."""
    return Settings()
