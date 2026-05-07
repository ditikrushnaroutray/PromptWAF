"""
PromptWAF Structured Logging — JSON-formatted security audit log.

Usage:
    from app.core.logging_config import setup_logging, get_security_logger
    setup_logging()
    logger = get_security_logger()
    logger.info("event", extra={...})
"""

import hashlib
import logging
import json
import sys
from datetime import datetime, timezone
from typing import Optional


class JSONSecurityFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON for structured ingestion
    (ELK, Datadog, CloudWatch, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge extra fields set via `extra={...}` on the log call
        for key in (
            "request_id", "event", "layer", "reason", "confidence",
            "original_prompt_hash", "original_prompt_preview",
            "normalized_prompt_preview", "source_ip", "blocked",
            "pattern_label", "similarity_score", "leakage_detected",
            "shadow_mode", "waf_mode", "latency_ms",
        ):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


def setup_logging() -> None:
    """Configure root and security loggers at startup."""
    # Root logger — INFO level, structured JSON to stderr
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONSecurityFormatter())
    root.addHandler(handler)

    # Dedicated security logger
    sec_logger = logging.getLogger("promptwaf.security")
    sec_logger.setLevel(logging.INFO)
    sec_logger.propagate = True  # Also output to root handler


def get_security_logger() -> logging.Logger:
    """Return the dedicated security audit logger."""
    return logging.getLogger("promptwaf.security")


def hash_prompt(text: str) -> str:
    """SHA-256 hash of the prompt for audit logging without storing raw text."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def truncate_for_log(text: str, max_len: int = 200) -> str:
    """Truncate prompt text for log previews — never log full prompts in production."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...[TRUNCATED]"


def log_waf_decision(
    logger: logging.Logger,
    *,
    request_id: str,
    blocked: bool,
    reason: str,
    layer: str,
    confidence: float = 0.0,
    original_prompt: str = "",
    normalized_prompt: str = "",
    source_ip: str = "",
    pattern_label: Optional[str] = None,
    similarity_score: Optional[float] = None,
    shadow_mode: bool = False,
    waf_mode: str = "BLOCK",
    latency_ms: Optional[float] = None,
) -> None:
    """Log a structured WAF verdict for the security audit trail."""
    level = logging.WARNING if blocked else logging.INFO

    if shadow_mode and blocked:
        event = "request_monitored"  # Detected but forwarded in MONITOR mode
    elif blocked:
        event = "request_blocked"
    else:
        event = "request_allowed"

    action_label = "MONITORED" if (shadow_mode and blocked) else ("BLOCKED" if blocked else "ALLOWED")

    logger.log(
        level,
        f"WAF {action_label}: {reason}",
        extra={
            "request_id": request_id,
            "event": event,
            "layer": layer,
            "reason": reason,
            "confidence": confidence,
            "blocked": blocked,
            "shadow_mode": shadow_mode,
            "waf_mode": waf_mode,
            "latency_ms": latency_ms,
            "original_prompt_hash": hash_prompt(original_prompt) if original_prompt else None,
            "original_prompt_preview": truncate_for_log(original_prompt) if original_prompt else None,
            "normalized_prompt_preview": truncate_for_log(normalized_prompt) if normalized_prompt else None,
            "source_ip": source_ip,
            "pattern_label": pattern_label,
            "similarity_score": similarity_score,
        },
    )
