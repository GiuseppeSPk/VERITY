"""Configuration management for VERITY."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434")

    # OpenAI
    openai_api_key: str = Field(default="")

    # Anthropic
    anthropic_api_key: str = Field(default="")

    # Google
    google_api_key: str = Field(default="")

    # e2b Sandbox
    e2b_api_key: str = Field(default="")

    # Default providers
    default_provider: Literal["ollama", "openai", "anthropic", "google"] = Field(default="ollama")
    default_model: str = Field(default="llama3.2")

    # Judge settings
    judge_provider: Literal["ollama", "openai", "anthropic", "google"] = Field(default="openai")
    judge_model: str = Field(default="gpt-4o-mini")

    # Database (PostgreSQL async or SQLite for dev)
    database_url: str = Field(default="sqlite+aiosqlite:///./VERITY.db")

    # Redis (for rate limiting and caching)
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Logging
    log_level: str = Field(default="INFO")

    # Debug mode (enables stack traces in error responses)
    debug: bool = Field(default=False)

    # CORS origins (comma-separated in env var)
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"]
    )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
