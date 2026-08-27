import secrets
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.db.models import APIKey
import hashlib

router = APIRouter()

class KeyGenerateRequest(BaseModel):
    email: EmailStr

class KeyGenerateResponse(BaseModel):
    raw_api_key: str
    owner_email: str
    message: str = "Please store this key securely. It will not be shown again."

@router.post("/v1/keys/generate", response_model=KeyGenerateResponse)
async def generate_api_key(request: KeyGenerateRequest, db: AsyncSession = Depends(get_db)):
    """
    Generates a new secure API key for the provided email.
    Stores only the hashed version in the database.
    """
    raw_token = secrets.token_urlsafe(32).rstrip('=')
    raw_key = f"pwaf_{raw_token}"
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:8]
    
    new_key_record = APIKey(
        key_hash=hashed_key,
        owner_email=request.email,
        prefix=prefix,
        is_active=True
    )
    
    db.add(new_key_record)
    await db.commit()
    await db.refresh(new_key_record)
    
    return KeyGenerateResponse(
        raw_api_key=raw_key,
        owner_email=request.email
    )
    