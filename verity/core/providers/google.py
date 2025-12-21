"""Google Gemini LLM provider.

Best for factuality and multimodal tasks.
"""

import time
from collections.abc import AsyncIterator

from verity.core.providers.base import BaseLLMProvider, LLMResponse


class GoogleProvider(BaseLLMProvider):
    """Provider for Google Gemini API.

    Recommended for:
    - Factuality tasks (68.8% FACTS score)
    - Multimodal inputs (images, video)
    - Long context windows (up to 2M tokens)
    """

    provider_name = "google"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.0-flash",
        timeout: float = 120.0,
    ):
        """Initialize Google Gemini provider.

        Args:
            api_key: Google API key (or from GOOGLE_API_KEY env)
            model: Default model to use
            timeout: Request timeout in seconds
        """
        import os

        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("Google API key required. Set GOOGLE_API_KEY env var or pass api_key.")

        self.model = model
        self.timeout = timeout
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

        # Lazy load httpx
        import httpx

        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Generate a response using Gemini."""
        start_time = time.perf_counter()

        # Build request payload
        contents = []

        if system_prompt:
            contents.append(
                {"role": "user", "parts": [{"text": f"System instruction: {system_prompt}"}]}
            )
            contents.append(
                {
                    "role": "model",
                    "parts": [{"text": "Understood. I will follow these instructions."}],
                }
            )

        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        response = await self._client.post(
            f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}",
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

        latency_ms = (time.perf_counter() - start_time) * 1000

        # Extract content from response
        content = ""
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            for part in parts:
                content += part.get("text", "")

        # Extract token counts
        usage = data.get("usageMetadata", {})

        return LLMResponse(
            content=content,
            model=self.model,
            provider=self.provider_name,
            tokens_input=usage.get("promptTokenCount", 0),
            tokens_output=usage.get("candidatesTokenCount", 0),
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
        """Stream a response from Gemini."""
        contents = []

        if system_prompt:
            contents.append(
                {"role": "user", "parts": [{"text": f"System instruction: {system_prompt}"}]}
            )
            contents.append({"role": "model", "parts": [{"text": "Understood."}]})

        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        async with self._client.stream(
            "POST",
            f"{self.base_url}/models/{self.model}:streamGenerateContent?key={self.api_key}",
            json=payload,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    import json

                    try:
                        # Remove 'data: ' prefix if present
                        if line.startswith("data: "):
                            line = line[6:]
                        data = json.loads(line)
                        candidates = data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            for part in parts:
                                text = part.get("text", "")
                                if text:
                                    yield text
                    except json.JSONDecodeError:
                        continue

    async def health_check(self) -> bool:
        """Check if Google API is available."""
        try:
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
