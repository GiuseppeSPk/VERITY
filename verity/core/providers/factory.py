"""Provider factory for creating LLM providers."""

from typing import Literal

from verity.config import get_settings
from verity.core.providers.base import BaseLLMProvider
from verity.core.providers.ollama import OllamaProvider
from verity.core.providers.openai import OpenAIProvider

ProviderType = Literal["ollama", "openai", "anthropic", "google"]


def create_provider(
    provider_type: ProviderType | None = None,
    model: str | None = None,
    **kwargs,
) -> BaseLLMProvider:
    """Create an LLM provider instance.

    Args:
        provider_type: Type of provider (ollama, openai, anthropic, google)
        model: Model to use (overrides settings default)
        **kwargs: Additional provider-specific arguments

    Returns:
        Configured LLM provider instance

    Raises:
        ValueError: If provider type is not supported
    """
    settings = get_settings()
    provider_type = provider_type or settings.default_provider
    model = model or settings.default_model

    if provider_type == "ollama":
        return OllamaProvider(
            base_url=kwargs.get("base_url", settings.ollama_base_url),
            model=model,
            **{k: v for k, v in kwargs.items() if k != "base_url"},
        )
    elif provider_type == "openai":
        return OpenAIProvider(
            api_key=kwargs.get("api_key", settings.openai_api_key),
            model=model,
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )
    elif provider_type == "anthropic":
        from verity.core.providers.anthropic import AnthropicProvider

        return AnthropicProvider(
            api_key=kwargs.get("api_key", settings.anthropic_api_key),
            model=model or "claude-sonnet-4-20250514",
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )
    elif provider_type == "google":
        from verity.core.providers.google import GoogleProvider

        return GoogleProvider(
            api_key=kwargs.get("api_key", settings.google_api_key),
            model=model or "gemini-2.0-flash",
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )
    else:
        raise ValueError(f"Unknown provider type: {provider_type}")


def create_judge_provider(**kwargs) -> BaseLLMProvider:
    """Create a provider configured for judging (typically stronger model).

    Returns:
        LLM provider configured with judge settings
    """
    settings = get_settings()
    return create_provider(
        provider_type=settings.judge_provider,
        model=settings.judge_model,
        **kwargs,
    )


def list_available_providers() -> list[str]:
    """List all available provider types.

    Returns:
        List of provider names
    """
    return ["ollama", "openai", "anthropic", "google"]
