import asyncio
import httpx
import os
import signal
import subprocess
import time

async def wait_for_server():
    for _ in range(30):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get("http://127.0.0.1:28451/health")
                if resp.status_code == 200:
                    return True
        except httpx.RequestError:
            time.sleep(0.5)
    return False

async def run_tests():
    # We don't have an auth key to create keys since /v1/keys/generate doesn't have an auth dependency?
    # Wait, let me check if /v1/keys/generate is protected.
    
    # 1. Generate an API Key
    print("\n--- Test 1: Generate API Key ---")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://127.0.0.1:28451/v1/keys/generate",
            json={"email": "tester@example.com"}
        )
        print(resp.status_code, resp.text)
        assert resp.status_code == 200
        data = resp.json()
        new_api_key = data["raw_api_key"]
        print(f"Generated Key: {new_api_key[:10]}...")
        print("✅ Key Generation Passed!")

    # 2. Test Invalid API Key
    print("\n--- Test 2: Invalid API Key (401) ---")
    headers_invalid = {
        "Authorization": "Bearer pwaf_invalid12345",
        "Content-Type": "application/json"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://127.0.0.1:28451/v1/chat/completions",
            headers=headers_invalid,
            json={"messages": [{"role": "user", "content": "Hello"}], "model": "gpt-3.5-turbo"}
        )
        print(resp.status_code, resp.text)
        assert resp.status_code == 401
        print("✅ Invalid Key properly blocked with 401!")

    # 3. Test Rate Limiting
    print("\n--- Test 3: Rate Limiting (429) ---")
    headers_valid = {
        "Authorization": f"Bearer {new_api_key}",
        "Content-Type": "application/json"
    }
    
    success_count = 0
    rate_limited = False
    
    # Send 15 requests rapidly. (Rate limit is 5/minute according to WAF_RATE_LIMIT override)
    async with httpx.AsyncClient() as client:
        for i in range(15):
            resp = await client.post(
                "http://127.0.0.1:28451/v1/chat/completions",
                headers=headers_valid,
                json={"messages": [{"role": "user", "content": "Hello"}], "model": "gpt-3.5-turbo"}
            )
            if resp.status_code == 429:
                rate_limited = True
                print(f"Request {i+1} got 429 Too Many Requests (Rate Limited) as expected!")
                break
            elif resp.status_code == 200:
                success_count += 1
            else:
                # Could be 502 Bad Gateway since WAF_OPENAI_API_KEY is fake
                pass
                
        assert rate_limited, "Did not receive a 429 rate limit response!"
        print("✅ Rate Limiting Passed!")

if __name__ == "__main__":
    print("Starting proxy server with Strict Rate Limits...")
    server = subprocess.Popen(
        ["source .venv/bin/activate && export PYTHONPATH=. && export WAF_RATE_LIMIT='5/minute' && export WAF_OPENAI_API_KEY='sk-mock' && uvicorn app.main:app --host 127.0.0.1 --port 28451"],
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    
    try:
        if asyncio.run(wait_for_server()):
            asyncio.run(run_tests())
        else:
            print("Server failed to start")
    finally:
        print("Killing server...")
        os.killpg(os.getpgid(server.pid), signal.SIGTERM)
