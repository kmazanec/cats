"""Environment-driven configuration. Loaded once at import time."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM provider
    openrouter_api_key: str = Field(default="", alias="OPENROUTER_API_KEY")
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1", alias="OPENROUTER_BASE_URL"
    )

    # Observability
    langsmith_api_key: str = Field(default="", alias="LANGSMITH_API_KEY")
    langsmith_project: str = Field(default="cats-dev", alias="LANGSMITH_PROJECT")
    langsmith_tracing: bool = Field(default=False, alias="LANGSMITH_TRACING")

    # Storage
    database_url: str = Field(
        default="postgresql+asyncpg://cats:cats@localhost:5433/cats",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6380/0", alias="REDIS_URL")

    # Default seeded target (used by `cats smoke`)
    default_target_name: str = Field(default="Local Co-Pilot", alias="DEFAULT_TARGET_NAME")
    default_target_base_url: str = Field(
        default="http://localhost:8300", alias="DEFAULT_TARGET_BASE_URL"
    )
    default_target_env: Literal["local", "staging", "prod"] = Field(
        default="local", alias="DEFAULT_TARGET_ENV"
    )

    # API
    api_host: str = Field(default="0.0.0.0", alias="CATS_API_HOST")
    api_port: int = Field(default=8400, alias="CATS_API_PORT")
    log_level: str = Field(default="INFO", alias="CATS_LOG_LEVEL")


@lru_cache(maxsize=1)
def _load() -> Settings:
    return Settings()


settings: Settings = _load()
