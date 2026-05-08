import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ---------------------------------------------------------------------------
# Database URL resolution — environment-first, safe fallback for containers
# ---------------------------------------------------------------------------
# 1. Reads DATABASE_URL from the environment (set via .env / docker-compose).
# 2. Falls back to /tmp/waf.db which is world-writable, so non-root Docker
#    users (e.g. 'wafuser') can always create the file without extra perms.
# ---------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URL: str = os.getenv(
    "DATABASE_URL", "sqlite:////tmp/waf.db"
)

# connect_args={"check_same_thread": False} is needed only for SQLite in FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()