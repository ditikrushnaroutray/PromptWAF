from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.proxy import router as proxy_router
from app.api.v1.keys import router as keys_router
from app.db.models import init_db
from app.core.security import limiter
from app.core.logging_config import setup_logging, get_security_logger
from app.core.config import WAF_MODE, WAF_VERSION, REDIS_URL
from app.core.metrics import waf_metrics


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that injects security headers on every response.
    WAF-specific headers (X-PromptWAF-Status, etc.) are set by the
    proxy route; this middleware adds baseline security headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Baseline security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
        )
        response.headers.setdefault("X-PromptWAF-Version", WAF_VERSION)

        return response


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize logging and database
    setup_logging()
    logger = get_security_logger()
    logger.info(
        f"PromptWAF v{WAF_VERSION} starting — mode={WAF_MODE.value}, "
        f"redis={'connected' if REDIS_URL != 'memory://' else 'disabled (in-memory)'}",
        extra={"event": "startup", "waf_mode": WAF_MODE.value},
    )
    init_db()
    yield
    # Shutdown
    logger.info(f"PromptWAF v{WAF_VERSION} shutting down", extra={"event": "shutdown"})


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PromptWAF",
    description="Enterprise-grade web application firewall proxy for LLM APIs. "
                "Multi-layer detection, fail-closed policy, streaming-aware leakage protection, "
                "distributed rate limiting, and shadow/monitor mode.",
    version=WAF_VERSION,
    lifespan=lifespan,
)

# Security Headers Middleware (outermost layer)
app.add_middleware(SecurityHeadersMiddleware)

# SlowAPI Setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Include Routers
app.include_router(proxy_router)
app.include_router(keys_router)


# ---------------------------------------------------------------------------
# Observability Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": WAF_VERSION,
        "waf": "active",
        "mode": WAF_MODE.value,
        "redis": "connected" if REDIS_URL != "memory://" else "in-memory",
    }


@app.get("/metrics")
async def metrics():
    """
    Prometheus-compatible metrics endpoint.

    Exports:
        - promptwaf_requests_total
        - promptwaf_blocked_total
        - promptwaf_monitored_total
        - promptwaf_allowed_total
        - promptwaf_errors_total
        - promptwaf_leakage_total
        - promptwaf_attacks_by_layer_total{layer="..."}
        - promptwaf_inspection_latency_avg_ms
        - promptwaf_inspection_latency_total_ms
        - promptwaf_inspection_latency_count
    """
    return Response(
        content=waf_metrics.to_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/metrics/json")
async def metrics_json():
    """JSON metrics snapshot for dashboarding and debugging."""
    snapshot = waf_metrics.get_snapshot()
    snapshot["waf_mode"] = WAF_MODE.value
    snapshot["version"] = WAF_VERSION
    return snapshot