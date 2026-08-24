import asyncio
import hashlib
import secrets
from sqlalchemy import select, func

from app.db.session import SessionLocal, init_db
from app.db.models import APIKey

async def seed():
    # Ensure tables exist first
    await init_db()
    
    async with SessionLocal() as db:
        # Check if any keys exist
        result = await db.execute(select(func.count(APIKey.id)))
        count = result.scalar()
        
        if count > 0:
            print(f"Database already contains {count} API keys. Seed skipped.")
            return

        # Generate a secure random string for the key
        # Removing padding '=' for a cleaner key
        raw_token = secrets.token_urlsafe(32).rstrip('=')
        raw_key = f"pwaf_{raw_token}"
        
        # Hash it using SHA-256
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Prefix for display (e.g., pwaf_aBc)
        prefix = raw_key[:8]
        
        # Create the key
        new_key = APIKey(
            key_hash=key_hash,
            owner_email="admin@promptwaf.local",
            prefix=prefix,
            permissions={"allow_all": True}
        )
        
        db.add(new_key)
        await db.commit()
        
        print("\n" + "="*50)
        print("🚀 Default Admin API Key Created!")
        print("="*50)
        print(f"RAW KEY: {raw_key}")
        print("IMPORTANT: Copy this key now. It will not be shown again.")
        print("="*50 + "\n")

if __name__ == "__main__":
    asyncio.run(seed())
