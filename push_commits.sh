#!/bin/bash
set -e

# Delete temporary scripts
rm -f test_auth.py run_test_with_logs.py

# Commit 1
git add app/services/output_scanner.py
git commit -m "feat(security): implement streaming output scanner with sliding window"

# Commit 2
git add app/services/openai_client.py
git commit -m "refactor(proxy): standardize upstream forwarding and exception mapping"

# Commit 3
git add app/api/v1/proxy.py
git commit -m "feat(proxy): integrate strict validation and multi-layer WAF orchestration"

# Commit 4
git add app/core/metrics.py
git commit -m "feat(observability): add output scanner latency metrics tracking"

# Commit 5
git add app/api/v1/keys.py
git commit -m "feat(auth): transition API key generation to SHA-256 with prefixes"

# Commit 6
git add app/core/security.py
git commit -m "feat(auth): refactor API key validation to native async and robust rate limiting"

# Commit 7
git add app/main.py
git commit -m "feat(proxy): implement custom JSON response for rate limit violations"

# Commit 8
git add verify_output_scanner.py
git commit -m "test: add verification script for output scanner chunk detection"

# Commit 9
git add verify_proxy_e2e.py
git commit -m "test: add end-to-end proxy and header injection verification"

# Commit 10
git add verify_auth_rate_limit.py
git commit -m "test: add verification for auth lifecycle and rate limiting"

# Commit 11 (catch anything else if there's any left)
git add -A
git commit -m "chore: final adjustments for PromptWAF phase 8" || true

# Push to origin main
git push origin main
