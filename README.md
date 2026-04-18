# PromptWAF

> A high-performance, drop-in Web Application Firewall (WAF) proxy designed to secure AI wrappers from prompt injection, jailbreaks, and system prompt leakage.

PromptWAF acts as a transparent, intelligent proxy between your application and the OpenAI API. It intercepts incoming requests, analyzes the payload for adversarial LLM attacks, and seamlessly forwards clean traffic. Built for developers who need enterprise-grade AI security without altering their existing OpenAI integrations.

## 🛡️ Why PromptWAF?
As LLM integrations scale, applications become vulnerable to prompt injection and unauthorized system leakage. PromptWAF solves this by providing:
* **Zero-Friction Integration:** Fully mirrors the OpenAI `chat/completions` API signature. Change your base URL, and your app is protected.
* **Intelligent Inspection:** Utilizes a lightweight, low-latency WAF engine to evaluate prompt intent before the payload reaches your expensive primary models.
* **Fail-Open Architecture:** Prioritizes availability. If the WAF engine experiences latency or errors, traffic is allowed through, ensuring your application never goes offline due to security timeouts.

## ✨ Key Features
* **Adversarial Defense:** Real-time blocking of prompt injections, jailbreaks, and exploit patterns targeting the last user message.
* **Native Streaming Support:** Fully supports `text/event-stream` to proxy OpenAI streaming responses without lag.
* **Secure Key Management:** Dedicated `POST /v1/keys/generate` endpoint. Issues secure API keys and stores only cryptographic hashes in the database.
* **Rate Limiting:** Built-in abuse prevention via SlowAPI (e.g., 50 requests/minute per key).
* **Transparent Auth Proxying:** Forwards client `Authorization` headers natively, or supports server-side injection via `WAF_OPENAI_API_KEY`.

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* OpenAI API Key

### Installation

1. Set up your virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate

