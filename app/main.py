from contextlib import asynccontextmanager
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.proxy import router as proxy_router
from app.api.v1.keys import router as keys_router
from app.db.models import init_db
from app.core.security import limiter

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize the database tables
    init_db()
    yield
    # Shutdown logic goes here if needed

app = FastAPI(
    title="PromptWAF",
    description="Drop-in web application firewall proxy for AI wrappers.",
    version="1.1.0",
    lifespan=lifespan
)

# SlowAPI Setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Include Routers
app.include_router(proxy_router)
app.include_router(keys_router)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok"}
    