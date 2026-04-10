from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from app.services.waf_engine import analyze_prompt
from app.services.openai_client import forward_to_openai

router = APIRouter()

@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Mirrors the OpenAI API signature. Validates auth, runs WAF engine, and forwards payload.
    """
    # Hardcoded token check
    auth_header = request.headers.get("Authorization")
    if auth_header != "Bearer pwaf_test_123":
        raise HTTPException(status_code=401, detail="Unauthorized")

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
    