import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, Float, DateTime, Integer, JSON, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class APIKey(Base):
    """Stores API keys and their metadata for WAF authentication."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    owner_email: Mapped[str] = mapped_column(String, index=True)
    prefix: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    permissions: Mapped[dict] = mapped_column(JSON, default={"allow_all": True})


class RequestLog(Base):
    """Persistent audit log for every WAF decision — powers the dashboard."""
    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    api_key_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("api_keys.id"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    method: Mapped[str] = mapped_column(String)
    path: Mapped[str] = mapped_column(String)
    status_code: Mapped[int] = mapped_column(Integer)
    waf_verdict: Mapped[str] = mapped_column(String, index=True)
    waf_layer: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    inspection_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    prompt_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    shadow_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String, nullable=True)