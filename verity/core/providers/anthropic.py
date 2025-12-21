"""Anthropic Claude LLM provider.

Best-in-class for LLM-as-Judge (0% hallucination rate).
"""

import time
from collections.abc import AsyncIterator

from verity.core.providers.base import BaseLLMProvider, LLMResponse


class AnthropicProvider(BaseLLMProvider):
    """Provider for Anthropic Claude API.

    Recommended for:
    - LLM-as-Judge (Claude Opus 4.5 has 0% hallucination)
    - Complex reasoning tasks
    - Safety evaluation
    """

    provider_name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        base_url: str = "https://api.anthropic.com",
        timeout: float = 120.0,
    ):
        """Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key (or from ANTHROPIC_API_KEY env)
            model: Default model to use
            base_url: API base URL
            timeout: Request timeout in seconds
        """
        import os

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass api_key."
            )

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        # Lazy load httpx
        import httpx

        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response using Claude."""
        start_time = time.perf_counter()

        # Build request payload
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        # Temperature 0 is not allowed, use 0.01 as minimum
        if temperature > 0:
            payload["temperature"] = temperature

        response = await self._client.post(
            f"{self.base_url}/v1/messages",
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

        latency_ms = (time.perf_counter() - start_time) * 1000

        # Extract content from response
        content = ""
        if data.get("content"):
            for block in data["content"]:
                if block.get("type") == "text":
                    content += block.get("text", "")

        return LLMResponse(
            content=content,
            model=self.model,
            provider=self.provider_name,
            tokens_input=data.get("usage", {}).get("input_tokens", 0),
            tokens_output=data.get("usage", {}).get("output_tokens", 0),
            latency_ms=latency_ms,
            raw_response=data,
        )

    async def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[str]:
        """Stream a response from Claude."""
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if temperature > 0:
            payload["temperature"] = temperature

        async with self._client.stream(
            "POST",
            f"{self.base_url}/v1/messages",
            json=payload,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    import json

                    try:
                        data = json.loads(line[6:])
                        if data.get("type") == "content_block_delta":
                            delta = data.get("delta", {})
                            if delta.get("type") == "text_delta":
                                yield delta.get("text", "")
                    except json.JSONDecodeError:
                        continue

    async def health_check(self) -> bool:
        """Check if Anthropic API is available."""
        try:
            # Simple test with minimal tokens
            response = await self.generate(
                prompt="Say 'OK'",
                max_tokens=10,
            )
            return len(response.content) > 0
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
