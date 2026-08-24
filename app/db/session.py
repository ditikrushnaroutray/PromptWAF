from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

from app.core.config import settings

# Create async engine. Connecting to sqlite for dev, or postgres for prod based on DATABASE_URL
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

# Async session factory
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()


async def get_db():
    """FastAPI dependency for yielding async database sessions."""
    async with SessionLocal() as session:
        yield session


async def init_db():
    """Create all tables defined by SQLAlchemy models."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)