from fastapi import FastAPI
from app.api.v1.proxy import router as proxy_router

app = FastAPI(
    title="PromptWAF",
    description="Drop-in web application firewall proxy for AI wrappers.",
    version="1.0.0"
)

# Include the main proxy routes
app.include_router(proxy_router)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok"}
    