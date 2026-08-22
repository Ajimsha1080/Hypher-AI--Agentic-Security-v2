"""
Centralized Configuration for Hypher AI Agent Runtime
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    ENV: str = "production"
    PORT: int = 8000
    LOG_LEVEL: str = "info"
    SERVICE_NAME: str = "hypher-agent-runtime"

    # Hypher Gateway
    HYPHER_GATEWAY_URL: str = os.getenv("HYPHER_GATEWAY_URL", "http://localhost:3000")
    HYPHER_API_TOKEN: str = os.getenv("HYPHER_API_TOKEN", "mcpsg_default_agent_token")
    DEFAULT_TENANT_ID: str = "tenant_default"
    DEFAULT_USER_ID: str = "user_default"

    # Multi-LLM Provider Layer
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")
    MODEL: str = os.getenv("MODEL", "gpt-4o")
    FALLBACK_MODEL: str = os.getenv("FALLBACK_MODEL", "gpt-3.5-turbo")
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048
    LLM_TIMEOUT_SECONDS: float = 30.0
    LLM_MAX_RETRIES: int = 2

    # Provider API Keys
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")

    # Persistence
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql://mcp_admin:secure_password_change_me@localhost:5432/mcp_security"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # Workflow Constraints
    MAX_AGENT_ITERATIONS: int = 10
    WORKFLOW_TIMEOUT_SECONDS: float = 60.0
    HITL_ENABLED: bool = True
    PII_MASKING_ENABLED: bool = True


settings = Settings()
