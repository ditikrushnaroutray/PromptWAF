import secrets
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import ApiKey
from app.core.security import get_password_hash

router = APIRouter()

class KeyGenerateRequest(BaseModel):
    email: EmailStr

class KeyGenerateResponse(BaseModel):
    raw_api_key: str
    owner_email: str
    message: str = "Please store this key securely. It will not be shown again."

@router.post("/v1/keys/generate", response_model=KeyGenerateResponse)
def generate_api_key(request: KeyGenerateRequest, db: Session = Depends(get_db)):
    """
    Generates a new secure API key for the provided email.
    Stores only the hashed version in the database.
    """
    raw_key = f"pwaf_{secrets.token_urlsafe(32)}"
    hashed_key = get_password_hash(raw_key)
    
    new_key_record = ApiKey(
        key_hash=hashed_key,
        owner_email=request.email,
        is_active=True
    )
    
    db.add(new_key_record)
    db.commit()
    db.refresh(new_key_record)
    
    return KeyGenerateResponse(
        raw_api_key=raw_key,
        owner_email=request.email
    )
    