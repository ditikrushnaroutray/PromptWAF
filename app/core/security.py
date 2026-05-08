import logging
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.db.session import get_db
from app.db.models import ApiKey
from app.core.config import REDIS_URL

_logger = logging.getLogger("promptwaf.security")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_key_identifier(request: Request) -> str:
    """Identify the user by their API key if present, otherwise by IP address."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return get_remote_address(request)

# Distributed rate limiter — uses Redis when REDIS_URL is set, otherwise
# falls back to in-memory storage. In multi-node deployments, all instances
# MUST point to the same Redis to share rate-limit counters.
limiter = Limiter(
    key_func=get_key_identifier,
    storage_uri=REDIS_URL,
)

_logger.info(
    f"Rate limiter initialized with backend: "
    f"{'Redis (' + REDIS_URL + ')' if REDIS_URL != 'memory://' else 'in-memory (single-node only)'}"
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
    