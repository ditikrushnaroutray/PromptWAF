import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import declarative_base

# Set environment before importing anything that parses config
os.environ["WAF_OPENAI_API_KEY"] = "sk-test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from app.db.models import APIKey, RequestLog
from app.db.session import Base

async def verify():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=True)
    print("Testing connection and table creation...")
    
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("Tables created successfully!")
        print("Models present:")
        for table in Base.metadata.sorted_tables:
            print(f"- {table.name}")
    except Exception as e:
        print(f"Failed to create models: {e}")

if __name__ == "__main__":
    asyncio.run(verify())
