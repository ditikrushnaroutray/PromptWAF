# =============================================================================
# PromptWAF — Production Multi-Stage Dockerfile
# =============================================================================
# Build:   docker build -t promptwaf:latest .
# Run:     docker run -p 8000:8000 --env-file .env promptwaf:latest
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build — Install dependencies in an isolated layer
# ---------------------------------------------------------------------------
FROM python:3.10-slim AS builder

WORKDIR /build

# Install build-time dependencies for packages with C extensions (bcrypt, scipy, scikit-learn)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install into a virtual environment so we can copy only the result
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Stage 2: Runtime — Minimal, non-root, production image
# ---------------------------------------------------------------------------
FROM python:3.10-slim AS runtime

LABEL maintainer="PromptWAF <security@promptwaf.dev>"
LABEL description="Enterprise-grade Web Application Firewall proxy for LLM APIs"
LABEL version="2.1.0"

# Install only the minimal runtime libraries (no compilers)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libffi8 curl && \
    rm -rf /var/lib/apt/lists/*

# Copy the pre-built virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create a non-root user for security
RUN groupadd --gid 1000 wafuser && \
    useradd --uid 1000 --gid wafuser --shell /bin/false --create-home wafuser

WORKDIR /home/wafuser/app

# Copy application code
COPY --chown=wafuser:wafuser app/ ./app/
COPY --chown=wafuser:wafuser requirements.txt .

# Switch to non-root user
USER wafuser

# Expose the application port
EXPOSE 8000

# Health check — uses the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with uvicorn — production settings
# - 0.0.0.0 binds to all interfaces (required inside Docker)
# - Workers default to 1; scale via UVICORN_WORKERS env var or orchestrator replicas
# - Access log disabled (structured JSON logging handles observability)
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--no-access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
