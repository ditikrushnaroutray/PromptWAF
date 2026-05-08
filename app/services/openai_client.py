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

from app.services.output_scanner import scan_streaming_response, scan_response_body
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


async def forward_to_openai(
    payload: dict,
    headers: dict,
    request_id: str = "",
    system_prompt: Optional[str] = None,
) -> StreamingResponse | dict:
    """
    Forward the payload to OpenAI and return the response.

    For streaming requests, the response is piped through the output scanner
    for leakage detection before being returned to the client.

    Args:
        payload: The validated request payload.
        headers: Incoming request headers (for fallback auth).
        request_id: Unique request ID for tracing.
        system_prompt: The system prompt for leakage detection.

    Returns:
        StreamingResponse for SSE, or dict for JSON responses.
    """
    forward_headers = _build_forward_headers(headers)
    is_stream = payload.get("stream", False)

    if is_stream:
        return await _handle_streaming(payload, forward_headers, request_id, system_prompt)
    else:
        return await _handle_non_streaming(payload, forward_headers, request_id, system_prompt)


async def _handle_streaming(
    payload: dict,
    headers: dict,
    request_id: str,
    system_prompt: Optional[str],
) -> StreamingResponse:
    """Handle streaming (SSE) response with output scanning."""

    async def _upstream_generator() -> AsyncGenerator[bytes, None]:
        """Stream chunks from OpenAI."""
        async with httpx.AsyncClient(timeout=OPENAI_TIMEOUT) as client:
            async with client.stream("POST", OPENAI_API_URL, json=payload, headers=headers) as response:
                if response.status_code != 200:
                    error_content = await response.aread()
                    yield error_content
                    return

                async for chunk in response.aiter_bytes():
                    yield chunk

    # Wrap the upstream generator with the leakage scanner
    scanned_generator = scan_streaming_response(
        upstream_generator=_upstream_generator(),
        system_prompt=system_prompt,
        request_id=request_id,
    )

    return StreamingResponse(
        scanned_generator,
        media_type="text/event-stream",
    )


async def _handle_non_streaming(
    payload: dict,
    headers: dict,
    request_id: str,
    system_prompt: Optional[str],
) -> dict:
    """Handle non-streaming JSON response with output scanning."""
    async with httpx.AsyncClient(timeout=OPENAI_TIMEOUT) as client:
        response = await client.post(
            OPENAI_API_URL, json=payload, headers=headers
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.json(),
        )

    response_data = response.json()

    # Scan for leakage in the response body
    if scan_response_body(response_data, system_prompt):
        logger.warning(
            "Non-streaming response blocked: leakage detected",
            extra={
                "event": "response_leakage_blocked",
                "request_id": request_id,
                "leakage_detected": True,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "message": "Security Violation: Leakage Detected",
                    "type": "security_violation",
                }
            },
        )

    return response_data