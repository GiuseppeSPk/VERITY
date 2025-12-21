"""Ollama LLM provider for local models."""

import time
from collections.abc import AsyncIterator

import httpx

from verity.core.providers.base import BaseLLMProvider, LLMResponse


class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama local LLM server."""

    provider_name = "ollama"

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: float = 120.0,
    ):
        """Initialize Ollama provider.

        Args:
            base_url: Ollama server URL
            model: Default model to use
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response using Ollama."""
        start_time = time.perf_counter()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await self._client.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
        )
        response.raise_for_status()
        data = response.json()

        latency_ms = (time.perf_counter() - start_time) * 1000

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=self.model,
            provider=self.provider_name,
            tokens_input=data.get("prompt_eval_count", 0),
            tokens_output=data.get("eval_count", 0),
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
        """Stream a response from Ollama."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with self._client.stream(
            "POST",
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": True,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    import json

                    data = json.loads(line)
                    content = data.get("message", {}).get("content", "")
                    if content:
                        yield content

    async def list_models(self) -> list[str]:
        """List available models on Ollama server."""
        response = await self._client.get(f"{self.base_url}/api/tags")
        response.raise_for_status()
        data = response.json()
        return [model["name"] for model in data.get("models", [])]

    async def health_check(self) -> bool:
        """Check if Ollama server is available."""
        try:
            response = await self._client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
