"""
PromptWAF OpenAI Client — Hardened proxy with proper resource management.

Forwards validated payloads to OpenAI, supporting both streaming (SSE) and
non-streaming (JSON) responses. Integrates with the output scanner for
leakage protection on streaming responses.
"""

import os
from typing import AsyncGenerator, Optional

import httpx
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from app.core.logging_config import get_security_logger

logger = get_security_logger()

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_TIMEOUT = httpx.Timeout(timeout=60.0, connect=10.0)


def _build_forward_headers(incoming_headers: dict) -> dict:
    """
    Build headers for the upstream OpenAI request.
    Strips incoming custom headers and injects the real API key.
    """
    openai_api_key = os.getenv("WAF_OPENAI_API_KEY")
    return {
        "Content-Type": "application/json",
        "Authorization": (
            f"Bearer {openai_api_key}"
            if openai_api_key
            else incoming_headers.get("authorization", "")
        ),
    }


async def forward_request(messages: list, headers: dict, **kwargs) -> dict:
    """
    Forward the non-streaming payload to OpenAI and return the JSON response.
    """
    forward_headers = _build_forward_headers(headers)
    payload = {"messages": messages, "stream": False, **kwargs}
    
    try:
        async with httpx.AsyncClient(timeout=OPENAI_TIMEOUT) as client:
            response = await client.post(
                OPENAI_API_URL, json=payload, headers=forward_headers
            )
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail={"error": "Gateway Timeout from OpenAI"})
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502, 
            detail={"error": f"Bad Gateway (OpenAI returned {exc.response.status_code})"}
        )
    except Exception as exc:
        logger.error(f"Upstream forward error: {exc}")
        raise HTTPException(status_code=500, detail={"error": "Internal Server Error during upstream forward"})


async def forward_stream(messages: list, headers: dict, **kwargs) -> AsyncGenerator[bytes, None]:
    """
    Forward the streaming payload to OpenAI and yield SSE chunks.
    """
    forward_headers = _build_forward_headers(headers)
    payload = {"messages": messages, "stream": True, **kwargs}
    
    try:
        async with httpx.AsyncClient(timeout=OPENAI_TIMEOUT) as client:
            async with client.stream("POST", OPENAI_API_URL, json=payload, headers=forward_headers) as response:
                if response.status_code != 200:
                    error_content = await response.aread()
                    yield error_content
                    return

                async for chunk in response.aiter_bytes():
                    yield chunk
    except httpx.TimeoutException:
        yield b'data: {"error": "Gateway Timeout from OpenAI"}\n\n'
        yield b'data: [DONE]\n\n'
    except Exception as exc:
        logger.error(f"Upstream stream error: {exc}")
        yield b'data: {"error": "Internal Server Error during stream forwarding"}\n\n'
        yield b'data: [DONE]\n\n'