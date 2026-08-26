"""
PromptWAF Logs API — Serves WAF audit logs for the dashboard.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import APIKey, RequestLog

router = APIRouter()


@router.get("/api/v1/logs")
def get_logs(
    limit: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    Return the most recent WAF audit logs, newest first.
    Used by the dashboard to populate the live event table.
    """
    logs = (
        db.query(WafLog)
        .order_by(WafLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() + "Z" if log.timestamp else "",
            "request_id": log.request_id,
            "source_ip": log.source_ip,
            "action": log.action,
            "layer": log.layer,
            "reason": log.reason,
            "confidence": log.confidence,
            "threat_score": log.threat_score,
            "payload_preview": log.payload_preview,
            "pattern_label": log.pattern_label,
            "latency_ms": round(log.latency_ms, 2) if log.latency_ms else 0.0,
            "waf_mode": log.waf_mode,
        }
        for log in logs
    ]
