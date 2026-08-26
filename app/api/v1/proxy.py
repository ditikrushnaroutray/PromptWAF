"""
PromptWAF Proxy Router — Hardened request handler with fail-closed policy
and shadow/monitor mode support.

Every request flows through:
    1. Payload extraction + validation
    2. WAF engine analysis (multi-layer, fail-closed)
    3. Metrics recording + structured logging
    4. Mode-dependent action (BLOCK → 403/504, MONITOR → forward + flag)
    5. Forward to OpenAI (if clean or MONITOR) with output scanning
    6. Security headers on all responses
"""

import uuid

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.services.waf_engine import waf_engine_instance, WafVerdict
from app.services.openai_client import forward_to_openai
from app.core.security import verify_api_key, limiter
from app.core.config import PROTECTED_SYSTEM_PROMPT, WAF_MODE, WafMode, RATE_LIMIT_STRING
from app.core.logging_config import get_security_logger, log_waf_decision, truncate_for_log
from app.core.metrics import waf_metrics, LatencyTimer
from app.db.models import APIKey, RequestLog
from app.db.session import get_db

router = APIRouter()
logger = get_security_logger()


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For if present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _make_blocked_response(
    verdict: WafVerdict, request_id: str, status_code: int = 403
) -> JSONResponse:
    """Build a standardized blocked response with security headers."""
    response = JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": f"Request blocked by PromptWAF: {verdict.reason}",
                "type": "prompt_injection_detected",
                "layer": verdict.layer,
                "request_id": request_id,
            }
        },
    )
    response.headers["X-PromptWAF-Status"] = "Blocked"
    response.headers["X-PromptWAF-Request-Id"] = request_id
    response.headers["X-PromptWAF-Layer"] = verdict.layer
    return response


def _make_error_response(
    verdict: WafVerdict, request_id: str
) -> JSONResponse:
    """Build a fail-closed error response (504 Gateway Timeout)."""
    response = JSONResponse(
        status_code=504,
        content={
            "error": {
                "message": f"PromptWAF security check failed: {verdict.reason}",
                "type": "waf_engine_error",
                "request_id": request_id,
            }
        },
    )
    response.headers["X-PromptWAF-Status"] = "Error"
    response.headers["X-PromptWAF-Request-Id"] = request_id
    return response


def _add_security_headers(
    response,
    request_id: str,
    status: str = "Clean",
    detected_attack: bool = False,
):
    """Inject security headers into the response."""
    if hasattr(response, "headers"):
        response.headers["X-PromptWAF-Status"] = status
        response.headers["X-PromptWAF-Request-Id"] = request_id
        response.headers["X-PromptWAF-Mode"] = WAF_MODE.value
        if detected_attack:
            response.headers["X-PromptWAF-Detected-Attack"] = "True"
    return response


def _extract_user_text(payload: dict) -> str:
    """Extract all user message content from the payload."""
    messages = payload.get("messages", [])
    user_texts = []
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        user_texts.append(item.get("text", ""))
            elif isinstance(content, str):
                user_texts.append(content)
    return " ".join(user_texts)

def _extract_system_prompt(payload: dict) -> Optional[str]:
    """Extract the system prompt from the payload for leakage protection."""
    messages = payload.get("messages", [])
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
    return None

@router.post("/v1/chat/completions")
@limiter.limit(RATE_LIMIT_STRING)
async def chat_completions(
    request: Request,
    api_key: APIKey = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """
    Mirrors the OpenAI API signature. Validates DB auth, runs multi-layer
    WAF engine with fail-closed policy, applies rate limiting, scans output
    for leakage, and forwards payload.

    Behavior depends on WAF_MODE:
        - BLOCK:   Malicious → 403/504 response (fail-closed)
        - MONITOR: Malicious → log + forward with X-PromptWAF-Detected-Attack header
    """
    request_id = str(uuid.uuid4())
    source_ip = _get_client_ip(request)
    is_shadow = WAF_MODE == WafMode.MONITOR

    # Track total requests
    waf_metrics.record_request()

    # --- 1. Payload Extraction ---
    try:
        payload = await request.json()
        raw_text = _extract_user_text(payload)
        system_prompt = _extract_system_prompt(payload)
    except Exception:
        response = JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "Invalid JSON payload",
                    "type": "invalid_request_error",
                    "request_id": request_id,
                }
            },
        )
        response.headers["X-PromptWAF-Status"] = "Error"
        response.headers["X-PromptWAF-Request-Id"] = request_id
        return response

    # --- 2. WAF Engine Analysis (Fail-Closed) with latency tracking ---
    latency_ms = 0.0
    try:
        verdict: WafVerdict = await waf_engine_instance.inspect(raw_text, system_prompt)
        latency_ms = verdict.latency_ms
        waf_metrics.record_latency(latency_ms)
    except Exception as exc:
        # Outer fail-closed: even if WafEngine's own error handling fails
        logger.error(
            f"Critical WAF engine failure: {exc}",
            extra={
                "request_id": request_id,
                "event": "waf_critical_failure",
                "source_ip": source_ip,
                "blocked": True,
                "shadow_mode": is_shadow,
                "waf_mode": WAF_MODE.value,
            },
        )
        verdict = WafVerdict(
            clean=False,
            blocked=True,
            monitored=False,
            reason=f"Critical WAF engine failure: {type(exc).__name__}",
            layer="critical_error",
            confidence=0.0,
            latency_ms=0.0
        )
        waf_metrics.record_error()

    # --- 3. Structured Logging ---
    original_prompt = verdict.original_text
    normalized_prompt = verdict.normalized_text

    # --- Persist to DB for dashboard ---
    if verdict.blocked:
        if is_shadow:
            action_label = "MONITOR"
        else:
            action_label = "BLOCK"
    else:
        action_label = "ALLOW"

    threat_score = verdict.confidence
    if verdict.similarity_score is not None:
        threat_score = max(threat_score, verdict.similarity_score)

    try:
        db_log = RequestLog(
            request_id=uuid.UUID(request_id),
            source_ip=source_ip,
            waf_verdict=action_label,
            waf_layer=verdict.layer,
            inspection_latency_ms=latency_ms,
            blocked=verdict.blocked,
            shadow_mode=is_shadow,
            method="POST",
            path="/v1/chat/completions",
            status_code=403 if verdict.blocked and not is_shadow else 200
        )
        db.add(db_log)
        db.commit()
    except Exception as exc:
        logger.error(f"Failed to persist WAF log: {exc}")

    log_waf_decision(
        logger,
        request_id=request_id,
        blocked=verdict.blocked,
        reason=verdict.reason,
        layer=verdict.layer,
        confidence=verdict.confidence,
        original_prompt=original_prompt,
        normalized_prompt=normalized_prompt,
        source_ip=source_ip,
        pattern_label=verdict.pattern_label,
        similarity_score=verdict.similarity_score,
        shadow_mode=is_shadow,
        waf_mode=WAF_MODE.value,
        latency_ms=latency_ms,
    )

    # --- 4. Mode-Dependent Action ---
    if verdict.blocked:
        # BLOCK mode: record metric and return error/blocked response
        is_engine_error = verdict.layer in (
            "error", "timeout", "critical_error", "llm_judge_error"
        )
        if is_engine_error:
            waf_metrics.record_error()
            return _make_error_response(verdict, request_id)

        with waf_metrics._lock:
            waf_metrics._total_blocked += 1
            
        return _make_blocked_response(verdict, request_id)
        
    elif verdict.monitored:
        # MONITOR mode: record metric, but DO NOT block
        with waf_metrics._lock:
            waf_metrics._total_monitored += 1
            
    else:
        waf_metrics.record_allowed()

    # --- 5. Forward to OpenAI with Output Scanning ---
    detected_attack = verdict.monitored

    try:
        # Determine system prompt for leakage detection (Option C: both sources)
        sys_prompt_for_leakage = system_prompt or PROTECTED_SYSTEM_PROMPT

        result = await forward_to_openai(
            payload=payload,
            headers=dict(request.headers),
            request_id=request_id,
            system_prompt=sys_prompt_for_leakage,
        )

        # Determine status label
        if detected_attack:
            status_label = "Monitored"
        else:
            status_label = "Clean"

        # Add security headers to the response
        if isinstance(result, (JSONResponse, StreamingResponse)):
            _add_security_headers(result, request_id, status_label, detected_attack)
            return result
        else:
            # Dict response from non-streaming
            response = JSONResponse(content=result)
            _add_security_headers(response, request_id, status_label, detected_attack)
            return response

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            f"Upstream forwarding error: {exc}",
            extra={
                "request_id": request_id,
                "event": "upstream_error",
                "source_ip": source_ip,
                "blocked": True,
                "shadow_mode": is_shadow,
                "waf_mode": WAF_MODE.value,
            },
        )
        waf_metrics.record_error()
        response = JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": "PromptWAF failed to reach upstream — fail-closed",
                    "type": "upstream_error",
                    "request_id": request_id,
                }
            },
        )
        response.headers["X-PromptWAF-Status"] = "Error"
        response.headers["X-PromptWAF-Request-Id"] = request_id
        return response