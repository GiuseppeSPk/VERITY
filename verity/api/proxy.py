"""VERITY Guardrails: High-Performance AI Firewall Proxy.

This is a prototype implementation of the Tier 1 Proxy Gateway.
It intercepts LLM requests, runs them through the filtering pipeline,
and forwards them to the target provider.
"""

import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
import httpx

from verity.api.routes.auth import get_current_user

router = APIRouter()

class ProxyRequest(BaseModel):
    """Compatible with OpenAI Chat Completions API."""
    model: str
    messages: List[Dict[str, str]]
    temperature: Optional[float] = 1.0
    stream: Optional[bool] = False

async def fast_filter_prompt(prompt: str) -> bool:
    """Tier 1: Fast Regex/Pattern matching.
    Returns True if safe, False if malicious.
    """
    # Placeholder for Tier 1 logic
    malicious_patterns = ["ignore all previous instructions", "system prompt", "DAN mode"]
    for pattern in malicious_patterns:
        if pattern.lower() in prompt.lower():
            return False
    return True

@router.post("/v1/chat/completions")
async def chat_proxy(
    request: ProxyRequest,
    user_info: dict = Depends(get_current_user)
):
    """The entry point for VERITY Guardrails Proxy."""
    start_time = time.perf_counter()
    
    # 1. Extract the last user message
    user_prompt = next((m["content"] for m in reversed(request.messages) if m["role"] == "user"), "")
    
    # 2. Run Tier 1: Fast Filter
    is_safe = await fast_filter_prompt(user_prompt)
    if not is_safe:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "VERITY_GUARDRAILS_BLOCK",
                "message": "Protocol Violation: Potential Prompt Injection detected.",
                "category": "Jailbreak"
            }
        )
    
    # 3. Forward to Target Provider (OpenAI/Vertex/etc)
    # This is a placeholder for actual forwarding logic
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    return {
        "id": "VERITY-guard-123",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": f"[VERITY PROTECTED] This is a proxy placeholder for model {request.model}"
                },
                "finish_reason": "stop",
                "index": 0
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        "VERITY_metadata": {
            "latency_overhead_ms": round(latency_ms, 2),
            "protection_status": "verified"
        }
    }
