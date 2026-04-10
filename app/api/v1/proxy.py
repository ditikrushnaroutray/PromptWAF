from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.services.waf_engine import analyze_prompt
from app.services.openai_client import forward_to_openai
from app.core.security import verify_api_key, limiter
from app.db.models import ApiKey

router = APIRouter()

@router.post("/v1/chat/completions")
@limiter.limit("50/minute")
async def chat_completions(
    request: Request,
    api_key: ApiKey = Depends(verify_api_key)
):
    """
    Mirrors the OpenAI API signature. Validates DB auth, runs WAF engine, applies rate limiting, and forwards payload.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # WAF engine check
    is_malicious = await analyze_prompt(payload)
    if is_malicious:
        return JSONResponse(
            status_code=400,
            content={"error": "Blocked by PromptWAF"}
        )

    # Forward the request to actual OpenAI if safe
    return await forward_to_openai(payload, dict(request.headers))
    