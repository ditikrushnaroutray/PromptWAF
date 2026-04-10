import os
import httpx
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

async def forward_to_openai(payload: dict, headers: dict):
    """
    Forwards the payload to the actual OpenAI API and returns the response.
    Handles both synchronous JSON and StreamingResponse.
    """
    url = "https://api.openai.com/v1/chat/completions"
    
    # We strip incoming custom headers and inject the real OpenAI API Key.
    # We fallback to the incoming authorization header if no WAF_OPENAI_API_KEY is found (for pass-through).
    openai_api_key = os.getenv("WAF_OPENAI_API_KEY")
    forward_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {openai_api_key}" if openai_api_key else headers.get("authorization", "")
    }

    client = httpx.AsyncClient()
    is_stream = payload.get("stream", False)

    if is_stream:
        async def stream_generator():
            async with client.stream("POST", url, json=payload, headers=forward_headers) as response:
                if response.status_code != 200:
                    # If OpenAI returns an error, yield the error body
                    error_content = await response.aread()
                    yield error_content
                    return
                    
                async for chunk in response.aiter_bytes():
                    yield chunk

        return StreamingResponse(stream_generator(), media_type="text/event-stream")
    else:
        response = await client.post(url, json=payload, headers=forward_headers, timeout=60.0)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.json())
            
        return response.json()
        