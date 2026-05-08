from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from datetime import datetime, timezone

from app.db.session import Base, engine


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True, nullable=False)
    owner_email = Column(String, index=True, nullable=False)
    is_active = Column(Boolean, default=True)


class WafLog(Base):
    """Persistent audit log for every WAF decision — powers the dashboard."""
    __tablename__ = "waf_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    request_id = Column(String, unique=True, index=True, nullable=False)
    source_ip = Column(String, default="unknown")
    action = Column(String, nullable=False)          # BLOCK, MONITOR, ALLOW
    layer = Column(String, default="clean")           # heuristic, semantic, etc.
    reason = Column(String, default="")
    confidence = Column(Float, default=0.0)
    threat_score = Column(Float, default=0.0)         # 0.0–1.0
    payload_preview = Column(String, default="")      # truncated prompt
    pattern_label = Column(String, nullable=True)
    latency_ms = Column(Float, default=0.0)
    waf_mode = Column(String, default="BLOCK")


def init_db():
    Base.metadata.create_all(bind=engine)