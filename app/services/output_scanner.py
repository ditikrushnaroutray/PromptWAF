"""
PromptWAF Output Scanner — Streaming-aware leakage detection.

Monitors the SSE (text/event-stream) response from OpenAI and terminates
the stream if the outgoing text matches the protected system prompt.

Uses a sliding-window buffer so partial matches across chunk boundaries
are detected.
"""

import json
from typing import AsyncGenerator, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.core.config import (
    PROTECTED_SYSTEM_PROMPT,
    LEAKAGE_SIMILARITY_THRESHOLD,
    LEAKAGE_WINDOW_SIZE,
)
from app.core.logging_config import get_security_logger

logger = get_security_logger()


# ---------------------------------------------------------------------------
# Leakage Similarity Computation
# ---------------------------------------------------------------------------

def _compute_leakage_similarity(text: str, system_prompt: str) -> float:
    """
    Compute normalized similarity between accumulated output text and the
    protected system prompt using TF-IDF char n-grams + cosine similarity.

    Returns a float 0.0 – 1.0.
    """
    if not system_prompt or not text:
        return 0.0

    # Short texts produce noisy TF-IDF — use direct substring check first
    prompt_lower = system_prompt.lower().strip()
    text_lower = text.lower().strip()

    # Fast-path: exact or near-exact substring match
    if len(prompt_lower) > 20 and prompt_lower[:50] in text_lower:
        return 1.0

    try:
        vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=5000,
            lowercase=True,
        )
        vectors = vectorizer.fit_transform([text, system_prompt])
        sim = cosine_similarity(vectors[0:1], vectors[1:2])
        return float(sim[0][0])
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# SSE Chunk Text Extraction
# ---------------------------------------------------------------------------

_SSE_DATA_PREFIX = "data: "


def _extract_text_from_sse_chunk(chunk_bytes: bytes) -> str:
    """
    Extract delta content text from an SSE chunk.

    SSE format:
        data: {"id":"...","choices":[{"delta":{"content":"Hello"}}]}
    """
    texts = []
    try:
        chunk_str = chunk_bytes.decode("utf-8", errors="replace")
        for line in chunk_str.split("\n"):
            line = line.strip()
            if not line.startswith(_SSE_DATA_PREFIX):
                continue
            json_str = line[len(_SSE_DATA_PREFIX):]
            if json_str == "[DONE]":
                continue
            try:
                data = json.loads(json_str)
                for choice in data.get("choices", []):
                    delta = choice.get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        texts.append(content)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
    except Exception:
        pass
    return "".join(texts)


# ---------------------------------------------------------------------------
# Non-Streaming Response Scanner
# ---------------------------------------------------------------------------

def scan_response_body(response_data: dict, system_prompt: Optional[str] = None) -> bool:
    """
    Scan a non-streaming JSON response for system prompt leakage.

    Returns True if leakage is detected, False if clean.
    """
    effective_prompt = system_prompt or PROTECTED_SYSTEM_PROMPT
    if not effective_prompt:
        return False

    try:
        choices = response_data.get("choices", [])
        for choice in choices:
            message = choice.get("message", {})
            content = message.get("content", "")
            if content:
                sim = _compute_leakage_similarity(content, effective_prompt)
                if sim >= LEAKAGE_SIMILARITY_THRESHOLD:
                    logger.warning(
                        "Output leakage detected in non-streaming response",
                        extra={
                            "event": "leakage_detected",
                            "similarity_score": sim,
                            "leakage_detected": True,
                        },
                    )
                    return True
    except Exception as exc:
        logger.error(f"Output scanner error: {exc}")
    return False


# ---------------------------------------------------------------------------
# Streaming Response Scanner (Sliding-Window)
# ---------------------------------------------------------------------------

async def scan_streaming_response(
    upstream_generator: AsyncGenerator[bytes, None],
    system_prompt: Optional[str] = None,
    request_id: str = "",
) -> AsyncGenerator[bytes, None]:
    """
    Wraps the upstream SSE generator with a sliding-window leakage scanner.

    Yields chunks to the client in real-time while accumulating text in a
    rolling buffer. If the buffer matches the protected system prompt above
    the leakage threshold, the stream is terminated with a security violation.
    """
    effective_prompt = system_prompt or PROTECTED_SYSTEM_PROMPT
    buffer = ""
    window_size = LEAKAGE_WINDOW_SIZE
    scan_enabled = bool(effective_prompt)
    check_interval = 5  # Check every N chunks to avoid excessive computation
    chunk_count = 0

    async for chunk in upstream_generator:
        if scan_enabled:
            # Extract text from this SSE chunk
            text = _extract_text_from_sse_chunk(chunk)
            if text:
                buffer += text
                chunk_count += 1

                # Trim buffer to sliding window size
                if len(buffer) > window_size:
                    buffer = buffer[-window_size:]

                # Periodic leakage check (not every chunk — performance)
                if chunk_count % check_interval == 0 and len(buffer) >= 30:
                    sim = _compute_leakage_similarity(buffer, effective_prompt)
                    if sim >= LEAKAGE_SIMILARITY_THRESHOLD:
                        logger.warning(
                            "STREAM TERMINATED: System prompt leakage detected",
                            extra={
                                "event": "stream_leakage_terminated",
                                "request_id": request_id,
                                "similarity_score": sim,
                                "leakage_detected": True,
                            },
                        )
                        # Send error event and terminate
                        error_event = (
                            'data: {"error": {"message": "Security Violation: '
                            'Leakage Detected", "type": "security_violation"}}\n\n'
                        )
                        yield error_event.encode("utf-8")
                        yield b"data: [DONE]\n\n"
                        return

        # Forward chunk to client
        yield chunk

    # Final check on remaining buffer
    if scan_enabled and len(buffer) >= 30:
        sim = _compute_leakage_similarity(buffer, effective_prompt)
        if sim >= LEAKAGE_SIMILARITY_THRESHOLD:
            logger.warning(
                "FINAL BUFFER: System prompt leakage detected at stream end",
                extra={
                    "event": "stream_leakage_final",
                    "request_id": request_id,
                    "similarity_score": sim,
                    "leakage_detected": True,
                },
            )
            error_event = (
                'data: {"error": {"message": "Security Violation: '
                'Leakage Detected", "type": "security_violation"}}\n\n'
            )
            yield error_event.encode("utf-8")
            yield b"data: [DONE]\n\n"
