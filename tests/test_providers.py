"""Tests for LLM providers."""

import pytest

from verity.core.providers import LLMResponse, OllamaProvider, OpenAIProvider


class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_tokens_total(self):
        """Test total tokens calculation."""
        response = LLMResponse(
            content="Hello",
            model="test",
            provider="test",
            tokens_input=10,
            tokens_output=5,
        )
        assert response.tokens_total == 15

    def test_default_values(self):
        """Test default values."""
        response = LLMResponse(content="Hi", model="m", provider="p")
        assert response.tokens_input == 0
        assert response.tokens_output == 0
        assert response.latency_ms == 0.0
        assert response.raw_response == {}


class TestOllamaProvider:
    """Tests for Ollama provider."""

    def test_init_defaults(self):
        """Test default initialization."""
        provider = OllamaProvider()
        assert provider.base_url == "http://localhost:11434"
        assert provider.model == "llama3.2"
        assert provider.provider_name == "ollama"

    def test_init_custom(self):
        """Test custom initialization."""
        provider = OllamaProvider(
            base_url="http://custom:1234",
            model="mistral",
        )
        assert provider.base_url == "http://custom:1234"
        assert provider.model == "mistral"


class TestOpenAIProvider:
    """Tests for OpenAI provider."""

    def test_init(self):
        """Test initialization."""
        provider = OpenAIProvider(api_key="test-key", model="gpt-4o")
        assert provider.model == "gpt-4o"
        assert provider.provider_name == "openai"


# Integration tests (require running services)
@pytest.mark.integration
@pytest.mark.asyncio
async def test_ollama_health_check():
    """Test Ollama health check (requires Ollama running)."""
    provider = OllamaProvider()
    is_healthy = await provider.health_check()
    # This will fail if Ollama is not running, which is expected
    assert isinstance(is_healthy, bool)
    await provider.close()
