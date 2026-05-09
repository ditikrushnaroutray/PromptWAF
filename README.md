<div align="center">

# 🛡️ PromptWAF

**Enterprise-Grade Web Application Firewall for LLM APIs**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

*A drop-in, transparent proxy that sits between your application and OpenAI to block prompt injection, jailbreaks, and system prompt leakage — in real time.*

</div>

---

## Why PromptWAF?

As LLM integrations scale, applications become vulnerable to adversarial prompt attacks. PromptWAF solves this by providing:

- **Zero-Friction Integration** — Fully mirrors the OpenAI `/v1/chat/completions` API. Change one line of code, and your app is protected.
- **Multi-Layer Detection** — Heuristic regex, semantic similarity (TF-IDF), and optional LLM judge working in concert.
- **Fail-Closed Architecture** — If the WAF engine errors or times out, traffic is **blocked**, not allowed through.
- **Streaming-Aware** — Monitors `text/event-stream` responses in real time with a sliding-window buffer to detect system prompt leakage.
- **Shadow Mode** — Deploy in `MONITOR` mode first to observe what *would* be blocked without affecting production traffic.

---

## Architecture

```
┌──────────────┐        ┌─────────────────────────────────────────────┐        ┌──────────────┐
│              │        │                 PromptWAF                    │        │              │
│  Your App    │───────▶│                                             │───────▶│   OpenAI     │
│  (Client)    │        │  ┌───────────┐  ┌──────────┐  ┌──────────┐ │        │   API        │
│              │◀───────│  │ Normalize │─▶│ Heuristic│─▶│ Semantic │ │◀───────│              │
│              │        │  │  (NFKC,   │  │ (Regex)  │  │ (TF-IDF) │ │        │              │
│              │        │  │  Base64)  │  │          │  │          │ │        │              │
│              │        │  └───────────┘  └──────────┘  └──────────┘ │        │              │
│              │        │           ▲                          │      │        │              │
│              │        │           │    Output Leakage Scan ◀─┘      │        │              │
│              │        │           │    (Sliding Window)             │        │              │
│              │        └───────────┼─────────────────────────────────┘        └──────────────┘
│              │                    │
│              │           ┌────────┴────────┐
│              │           │   Redis         │
│              │           │ (Rate Limiting) │
│              │           └────────┬────────┘
│              │                    │
│              │           ┌────────┴────────┐
│              │           │   Prometheus    │
│              │           │  (/metrics)     │
│              │           └─────────────────┘
└──────────────┘
```

### Security Layers

| Layer | Engine | Latency | What It Catches |
|-------|--------|---------|-----------------|
| **1. Input Normalization** | Unicode NFKC + zero-width strip + Base64/Hex decode | µs | Homoglyph attacks, encoded payloads, invisible character injection |
| **2. Heuristic Regex** | 17 compiled patterns across 5 categories | µs | "Ignore all previous instructions", DAN mode, system prompt extraction |
| **3. Semantic Similarity** | TF-IDF char n-grams + cosine similarity | ms | Rephrased jailbreaks that evade regex |
| **4. LLM Judge** *(optional)* | GPT-4o-mini classification | ~500ms | Novel/creative attacks not in pattern library |
| **5. Output Scanner** | Sliding-window buffer on SSE stream | µs/chunk | System prompt leakage in model responses |

---

## Quick Start (Docker — Recommended)

### 1. Clone & Configure

```bash
git clone https://github.com/ditikrushnaroutray/PromptWAF.git
cd PromptWAF

# Create your environment file from the template
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Required — Your real OpenAI API key
WAF_OPENAI_API_KEY=sk-your-openai-api-key-here

# Required — Your app's system prompt (for leakage detection)
PROTECTED_SYSTEM_PROMPT="You are a helpful customer support agent for Acme Corp..."

# Optional — Start in MONITOR mode for safe rollout (default: BLOCK)
WAF_MODE=MONITOR
```

### 2. Launch the Stack

```bash
docker compose up -d
```

This starts three services:

| Service | Port | Purpose |
|---------|------|---------|
| `prompt-waf` | `8000` | The WAF proxy |
| `redis` | `6379` | Distributed rate limiting |
| `prometheus` | `9090` | Metrics dashboard |

### 3. Verify

```bash
# Health check
curl http://localhost:8000/health

# Expected:
# {"status":"ok","version":"2.1.0","waf":"active","mode":"BLOCK","redis":"connected"}
```

---

## One-Line Integration

PromptWAF is a **transparent proxy** — it mirrors the exact OpenAI API signature. Point your SDK at the proxy instead of OpenAI, and you're protected.

### Python (OpenAI SDK)

```python
from openai import OpenAI

# Before (direct to OpenAI):
# client = OpenAI(api_key="sk-your-key")

# After (through PromptWAF):
client = OpenAI(
    api_key="pwaf_your-promptwaf-api-key",   # PromptWAF API key
    base_url="http://localhost:8000",         # ← Point to your PromptWAF instance
)

# Usage is identical — no other code changes needed
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello, world!"}],
    stream=True,  # Streaming is fully supported
)
```

### Node.js (OpenAI SDK)

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "pwaf_your-promptwaf-api-key",
  baseURL: "http://localhost:8000",  // ← Point to PromptWAF
});

const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Hello, world!" }],
});
```

### cURL

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer pwaf_your-promptwaf-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "What is the capital of France?"}]
  }'
```

### Generate a PromptWAF API Key

```bash
curl -X POST http://localhost:8000/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@yourcompany.com"}'

# Response:
# {
#   "raw_api_key": "pwaf_aBcDeFgHiJkLmNoPqRsTuVwXyZ...",
#   "owner_email": "dev@yourcompany.com",
#   "message": "Please store this key securely. It will not be shown again."
# }
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WAF_OPENAI_API_KEY` | ✅ | — | Your real OpenAI API key for upstream forwarding |
| `WAF_MODE` | No | `BLOCK` | `BLOCK` = fail-closed enforcement. `MONITOR` = log-only shadow mode |
| `PROTECTED_SYSTEM_PROMPT` | Recommended | `""` | Your app's system prompt text — used to detect leakage in responses |
| `REDIS_URL` | No | `memory://` | Redis connection string for distributed rate limiting. Set for multi-node |
| `WAF_RATE_LIMIT` | No | `50/minute` | Rate limit per API key or IP address |
| `WAF_TIMEOUT_SECONDS` | No | `5.0` | Max seconds for WAF analysis before fail-closed block |
| `MAX_PROMPT_LENGTH` | No | `50000` | Maximum prompt character count before auto-block |
| `SEMANTIC_SIMILARITY_THRESHOLD` | No | `0.8` | Cosine similarity threshold for semantic jailbreak detection (0.0–1.0) |
| `LEAKAGE_SIMILARITY_THRESHOLD` | No | `0.7` | Similarity threshold for output leakage detection (0.0–1.0) |
| `WAF_ENABLE_LLM_JUDGE` | No | `false` | Enable the optional GPT-4o-mini LLM judge (Layer 3). Adds latency and cost |
| `WAF_FAIL_CLOSED` | No | `true` | If `true`, WAF engine errors result in blocked traffic |

---

## Security Modes

### `BLOCK` Mode (Default — Production)

The WAF enforces all security layers. Malicious requests are blocked with HTTP `403` and the response header `X-PromptWAF-Status: Blocked`.

```
Client ──▶ PromptWAF ──✕ BLOCKED (403)
                       │
                       └──▶ Structured JSON log (event: request_blocked)
```

### `MONITOR` Mode (Shadow — Safe Rollout)

The WAF performs all detection but **never blocks**. Malicious requests are forwarded to OpenAI with an additional header `X-PromptWAF-Detected-Attack: True`. All violations are logged.

```
Client ──▶ PromptWAF ──▶ OpenAI ──▶ Response
                       │                 │
                       └──▶ Log: "attack detected (not blocked)"
                            Header: X-PromptWAF-Detected-Attack: True
```

> **Recommended rollout:** Deploy in `MONITOR` mode first, review the logs for false positives, then switch to `BLOCK`.

---

## Observability & Metrics

### Prometheus Endpoint

PromptWAF exposes a Prometheus-compatible `/metrics` endpoint:

```bash
curl http://localhost:8000/metrics
```

```text
# HELP promptwaf_requests_total Total requests processed by PromptWAF.
# TYPE promptwaf_requests_total counter
promptwaf_requests_total 1542

# HELP promptwaf_blocked_total Total requests blocked by PromptWAF.
# TYPE promptwaf_blocked_total counter
promptwaf_blocked_total 23

# HELP promptwaf_monitored_total Total attacks detected in MONITOR mode (not blocked).
# TYPE promptwaf_monitored_total counter
promptwaf_monitored_total 5

# HELP promptwaf_attacks_by_layer_total Attacks detected per WAF layer.
# TYPE promptwaf_attacks_by_layer_total counter
promptwaf_attacks_by_layer_total{layer="heuristic"} 18
promptwaf_attacks_by_layer_total{layer="semantic"} 5
promptwaf_attacks_by_layer_total{layer="leakage"} 0

# HELP promptwaf_inspection_latency_avg_ms Average WAF inspection latency in milliseconds.
# TYPE promptwaf_inspection_latency_avg_ms gauge
promptwaf_inspection_latency_avg_ms 2.341
```

### JSON Metrics

```bash
curl http://localhost:8000/metrics/json
```

### Prometheus Dashboard

With the included `docker-compose.yml`, Prometheus is pre-configured to scrape PromptWAF at `http://prompt-waf:8000/metrics` every 15 seconds.

Access the Prometheus UI at **http://localhost:9090** and query metrics like:

```promql
# Attack rate over last 5 minutes
rate(promptwaf_blocked_total[5m])

# Per-layer breakdown
promptwaf_attacks_by_layer_total

# Inspection latency trend
promptwaf_inspection_latency_avg_ms
```

### Structured JSON Logs

Every WAF decision is logged as structured JSON to stderr:

```json
{
  "timestamp": "2026-05-07T12:00:00.000Z",
  "level": "WARNING",
  "event": "request_blocked",
  "request_id": "a1b2c3d4-...",
  "layer": "heuristic",
  "reason": "Heuristic match: instruction_override",
  "confidence": 1.0,
  "blocked": true,
  "shadow_mode": false,
  "waf_mode": "BLOCK",
  "latency_ms": 1.82,
  "source_ip": "203.0.113.42",
  "original_prompt_hash": "e3b0c44298fc1c14..."
}
```

---

## Response Headers

Every response from PromptWAF includes security headers:

| Header | Values | Description |
|--------|--------|-------------|
| `X-PromptWAF-Status` | `Clean` / `Blocked` / `Monitored` / `Error` | WAF verdict for this request |
| `X-PromptWAF-Request-Id` | UUID | Unique ID for log correlation |
| `X-PromptWAF-Mode` | `BLOCK` / `MONITOR` | Current WAF enforcement mode |
| `X-PromptWAF-Layer` | `heuristic` / `semantic` / etc. | Which layer triggered the block |
| `X-PromptWAF-Detected-Attack` | `True` | Only present in MONITOR mode when attack detected |
| `X-PromptWAF-Version` | `2.1.0` | WAF engine version |

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/v1/chat/completions` | Bearer token | OpenAI-compatible proxy (main WAF endpoint) |
| `POST` | `/v1/keys/generate` | None | Generate a new PromptWAF API key |
| `GET`  | `/health` | None | Health check + status |
| `GET`  | `/metrics` | None | Prometheus metrics (text format) |
| `GET`  | `/metrics/json` | None | Metrics snapshot (JSON) |

---

## Development Setup (Without Docker)

```bash
# Clone the repository
git clone https://github.com/ditikrushnaroutray/PromptWAF.git
cd PromptWAF

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run the development server
uvicorn app.main:app --reload --port 8000
```

### Running Tests

```bash
# All tests (99 tests — security + regression)
python -m pytest tests/ -v

# Adversarial payload regression suite only
python -m pytest tests/security/test_payloads.py -v

# Quick check — 100% detection rate
python -m pytest tests/security/test_payloads.py::TestCoverageReport -v
```

---

## Project Structure

```
PromptWAF/
├── app/
│   ├── main.py                     # FastAPI app, middleware, /health, /metrics
│   ├── api/v1/
│   │   ├── proxy.py                # Main WAF proxy route (/v1/chat/completions)
│   │   └── keys.py                 # API key generation
│   ├── core/
│   │   ├── config.py               # All WAF configuration & regex patterns
│   │   ├── security.py             # Auth, rate limiting (Redis-backed)
│   │   ├── logging_config.py       # Structured JSON logging
│   │   └── metrics.py              # Prometheus metrics collector
│   ├── services/
│   │   ├── waf_engine.py           # Multi-layer detection engine
│   │   ├── normalizer.py           # Input de-obfuscation (NFKC, Base64, hex)
│   │   ├── output_scanner.py       # Streaming leakage detection
│   │   └── openai_client.py        # Hardened upstream proxy
│   └── db/
│       ├── models.py               # SQLAlchemy models
│       └── session.py              # Database session
├── tests/
│   ├── test_waf_security.py        # Unit tests (37 tests)
│   └── security/
│       ├── adversarial_payloads.json  # 30 adversarial test payloads
│       └── test_payloads.py        # Regression suite (62 tests)
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml              # Full stack (WAF + Redis + Prometheus)
├── prometheus.yml                  # Prometheus scrape config
├── .env.example                    # Environment variable template
└── requirements.txt                # Python dependencies
```

---

## License

GNU General Public License v3 © PromptWAF Contributors
