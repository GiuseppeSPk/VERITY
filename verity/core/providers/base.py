"""Base LLM provider interface."""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    provider: str
    tokens_input: int = 0
    tokens_output: int = 0
    latency_ms: float = 0.0
    raw_response: dict = field(default_factory=dict)

    @property
    def tokens_total(self) -> int:
        """Total tokens used."""
        return self.tokens_input + self.tokens_output


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    provider_name: str = "base"

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response from the LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate

        Returns:
            LLMResponse with generated content
        """
        ...

    @abstractmethod
    async def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[str]:
        """Stream a response from the LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Yields:
            Chunks of generated text
        """
        ...

    async def health_check(self) -> bool:
        """Check if the provider is available.

        Returns:
            True if provider is healthy
        """
        try:
            response = await self.generate("Say 'OK'", max_tokens=10)
            return len(response.content) > 0
        except Exception:
            return False
