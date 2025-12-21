"""OpenAI LLM provider."""

import time
from collections.abc import AsyncIterator

from openai import AsyncOpenAI

from verity.core.providers.base import BaseLLMProvider, LLMResponse


class OpenAIProvider(BaseLLMProvider):
    """Provider for OpenAI API."""

    provider_name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: str | None = None,
    ):
        """Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key
            model: Default model to use
            base_url: Optional custom base URL (for compatible APIs)
        """
        self.model = model
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response using OpenAI."""
        start_time = time.perf_counter()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore
            temperature=temperature,
            max_tokens=max_tokens,
        )

        latency_ms = (time.perf_counter() - start_time) * 1000

        content = response.choices[0].message.content or ""
        usage = response.usage

        return LLMResponse(
            content=content,
            model=self.model,
            provider=self.provider_name,
            tokens_input=usage.prompt_tokens if usage else 0,
            tokens_output=usage.completion_tokens if usage else 0,
            latency_ms=latency_ms,
            raw_response=response.model_dump(),
        )

    async def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[str]:
        """Stream a response from OpenAI."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        stream = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )

        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    async def close(self) -> None:
        """Close the client."""
        await self._client.close()
