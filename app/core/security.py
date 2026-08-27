import logging
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from slowapi import Limiter
from slowapi.util import get_remote_address
import hashlib
from app.db.session import get_db
from app.db.models import APIKey
from app.core.config import REDIS_URL

_logger = logging.getLogger("promptwaf.security")


def get_key_identifier(request: Request) -> str:
    """Identify the user by their API key hash if present, otherwise by IP address."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        raw_key = auth_header.split(" ")[1]
        return hashlib.sha256(raw_key.encode()).hexdigest()
    return get_remote_address(request)

# Distributed rate limiter
try:
    if REDIS_URL.startswith("redis"):
        limiter = Limiter(key_func=get_key_identifier, storage_uri=REDIS_URL)
    else:
        limiter = Limiter(key_func=get_key_identifier)
except Exception as e:
    _logger.warning(f"Failed to connect to Redis, falling back to memory: {e}")
    limiter = Limiter(key_func=get_key_identifier)

_logger.info(
    f"Rate limiter initialized with backend: "
    f"{'Redis (' + REDIS_URL + ')' if REDIS_URL != 'memory://' else 'in-memory (single-node only)'}"
)

security_scheme = HTTPBearer()

def get_password_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password

async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> APIKey:
    """Dependency to extract and verify the API key from the Bearer token."""
    raw_key = credentials.credentials
    
    if not raw_key.startswith("pwaf_"):
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key format",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # We fetch all active keys and check the hash. 
    # In a high-performance system, consider caching verified keys in Redis.
    result = await db.execute(select(APIKey).filter(APIKey.is_active == True))
    api_keys = result.scalars().all()
    
    for db_key in api_keys:
        if verify_password(raw_key, db_key.key_hash):
            return db_key
            
    raise HTTPException(
        status_code=401,
        detail="Invalid or inactive API Key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    