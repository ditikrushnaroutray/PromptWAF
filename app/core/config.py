"""
PromptWAF Configuration — Central security constants and environment-driven settings.
"""

import os
import re
import secrets
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class WafMode(str, Enum):
    BLOCK = "BLOCK"
    MONITOR = "MONITOR"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    WAF_OPENAI_API_KEY: str = Field(..., description="Actual OpenAI API key for upstream forwarding")
    WAF_MODE: WafMode = Field(default=WafMode.BLOCK)
    PROTECTED_SYSTEM_PROMPT: str = Field(default="")
    REDIS_URL: str = Field(default="memory://")
    WAF_RATE_LIMIT: str = Field(default="50/minute")
    WAF_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0.0)
    MAX_PROMPT_LENGTH: int = Field(default=50000, gt=0)
    SEMANTIC_SIMILARITY_THRESHOLD: float = Field(default=0.8, ge=0.0, le=1.0)
    LEAKAGE_SIMILARITY_THRESHOLD: float = Field(default=0.7, ge=0.0, le=1.0)
    WAF_ENABLE_LLM_JUDGE: bool = Field(default=False)
    WAF_FAIL_CLOSED: bool = Field(default=True)
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:////tmp/waf.db")
    MAX_NORMALIZATION_DEPTH: int = Field(default=3, ge=1)
    ENABLE_NORMALIZATION: bool = Field(default=True)
    SEMANTIC_CORPUS_PATH: Optional[str] = Field(default=None)
    @field_validator("WAF_OPENAI_API_KEY")
    def validate_api_key(cls, v):
        if not v or not v.strip():
            raise ValueError("WAF_OPENAI_API_KEY cannot be empty")
        return v

# Optional fallback for environments where the key might be intentionally absent at import time (like CI).
# But pydantic will enforce the required field on initialization, so we mock it for tests if needed.
if os.getenv("PYTEST_CURRENT_TEST"):
    os.environ["WAF_OPENAI_API_KEY"] = "sk-test"

settings = Settings()

# Aliases for backwards compatibility with the rest of the application
WAF_MODE = settings.WAF_MODE
REDIS_URL = settings.REDIS_URL
RATE_LIMIT_STRING = settings.WAF_RATE_LIMIT
WAF_TIMEOUT_SECONDS = settings.WAF_TIMEOUT_SECONDS
MAX_PROMPT_LENGTH = settings.MAX_PROMPT_LENGTH
FAIL_CLOSED = settings.WAF_FAIL_CLOSED
PROTECTED_SYSTEM_PROMPT = settings.PROTECTED_SYSTEM_PROMPT
SEMANTIC_SIMILARITY_THRESHOLD = settings.SEMANTIC_SIMILARITY_THRESHOLD
LEAKAGE_SIMILARITY_THRESHOLD = settings.LEAKAGE_SIMILARITY_THRESHOLD
WAF_ENABLE_LLM_JUDGE = settings.WAF_ENABLE_LLM_JUDGE
WAF_VERSION = "2.1.0"
LEAKAGE_WINDOW_SIZE = 500
MAX_NORMALIZATION_DEPTH = settings.MAX_NORMALIZATION_DEPTH
ENABLE_NORMALIZATION = settings.ENABLE_NORMALIZATION

# ---------------------------------------------------------------------------
# Zero-Width & Invisible Characters to Strip
# ---------------------------------------------------------------------------
INVISIBLE_CHARS: set = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u00ad", "\ufeff", 
    "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\u180e", 
    "\ufff9", "\ufffa", "\ufffb",
}
