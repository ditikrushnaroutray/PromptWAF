import os
import secrets
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.db.session import get_db
from app.db.models import ApiKey

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fallback to memory if Redis is not configured
REDIS_URL = os.environ.get("REDIS_URL", "memory://")

def get_key_identifier(request: Request) -> str:
    """Identify the user by their API key if present, otherwise by IP address."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return get_remote_address(request)

limiter = Limiter(
    key_func=get_key_identifier,
    storage_uri=REDIS_URL
)

security_scheme = HTTPBearer()

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
    db: Session = Depends(get_db)
) -> ApiKey:
    """Dependency to extract and verify the API key from the Bearer token."""
    raw_key = credentials.credentials
    
    # We fetch all active keys and check the hash. 
    # In a high-performance system, consider caching verified keys in Redis.
    api_keys = db.query(ApiKey).filter(ApiKey.is_active == True).all()
    
    for db_key in api_keys:
        if verify_password(raw_key, db_key.key_hash):
            return db_key
            
    raise HTTPException(
        status_code=401,
        detail="Invalid or inactive API Key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    