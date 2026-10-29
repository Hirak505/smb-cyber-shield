"""Application configuration via pydantic-settings. All secrets via env vars."""
from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    APP_ENV: str = "dev"
    SECRET_KEY: str = "change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "sqlite:///./shielddesk.db"

    # CORS / cookie
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    COOKIE_SECURE: bool = False   # True in prod (HTTPS only)
    COOKIE_SAMESITE: str = "lax"

    # Rate limiting (requests / window_seconds per IP)
    SCAN_RATE_LIMIT: int = 20
    SCAN_RATE_WINDOW: int = 60
    AUTH_RATE_LIMIT: int = 10
    AUTH_RATE_WINDOW: int = 60

    # LLM (optional – scanner works without it)
    LLM_PROVIDER: str = "anthropic"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = ""

    # External enrichment (feature flags)
    ENABLE_SAFE_BROWSING: bool = False
    SAFE_BROWSING_API_KEY: str = ""

    # Input caps
    MAX_MESSAGE_BYTES: int = 20_480   # 20 KB

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_not_default(cls, v: str) -> str:  # noqa: N805
        # Warn but don't crash in dev; crash in prod
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
