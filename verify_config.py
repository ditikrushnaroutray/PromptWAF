import os
from app.core.config import settings

def main():
    print("Loading PromptWAF Configuration...")
    print(f"WAF_MODE: {settings.WAF_MODE.value}")
    
    # Mask API key for security
    api_key = settings.WAF_OPENAI_API_KEY
    if api_key:
        masked = api_key[:5] + "*" * (len(api_key) - 9) + api_key[-4:] if len(api_key) > 9 else "***"
        print(f"WAF_OPENAI_API_KEY: {masked}")
        
    print(f"PROTECTED_SYSTEM_PROMPT: {settings.PROTECTED_SYSTEM_PROMPT}")
    print(f"REDIS_URL: {settings.REDIS_URL}")
    print(f"WAF_RATE_LIMIT: {settings.WAF_RATE_LIMIT}")
    print(f"WAF_TIMEOUT_SECONDS: {settings.WAF_TIMEOUT_SECONDS}")
    print(f"MAX_PROMPT_LENGTH: {settings.MAX_PROMPT_LENGTH}")
    print(f"SEMANTIC_SIMILARITY_THRESHOLD: {settings.SEMANTIC_SIMILARITY_THRESHOLD}")
    print(f"LEAKAGE_SIMILARITY_THRESHOLD: {settings.LEAKAGE_SIMILARITY_THRESHOLD}")
    print(f"WAF_ENABLE_LLM_JUDGE: {settings.WAF_ENABLE_LLM_JUDGE}")
    print(f"WAF_FAIL_CLOSED: {settings.WAF_FAIL_CLOSED}")
    print(f"DATABASE_URL: {settings.DATABASE_URL}")
    print("Configuration loaded successfully without validation errors!")

if __name__ == "__main__":
    # In order to verify the config, we simulate an API key if not set.
    if "WAF_OPENAI_API_KEY" not in os.environ:
        os.environ["WAF_OPENAI_API_KEY"] = "sk-test1234567890"
    
    # Since config is imported top-level, it might have already validated with the env vars at import.
    # Therefore, we reload settings manually to capture the newly injected key if it was missing.
    from pydantic_settings import BaseSettings
    from app.core.config import Settings
    
    global settings
    settings = Settings()
    
    main()
