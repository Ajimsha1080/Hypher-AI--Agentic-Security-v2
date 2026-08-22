"""
Multi-LLM Provider Layer for Hypher AI
Uses LiteLLM abstraction to support OpenAI, Anthropic, Gemini, local models with automatic fallback, retries, and token/cost metrics.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from agent_runtime.config import settings

logger = logging.getLogger("hypher.llm")


class LLMResponse(BaseModel):
    content: str
    model_used: str
    provider_used: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    latency_ms: int = 0
    fallback_triggered: bool = False
    error: Optional[str] = None


class MultiLLMProvider:
    """
    LiteLLM wrapper providing robust model calls, automatic fallback,
    retry handling, token tracking, and structured output parsing.
    """

    def __init__(
        self,
        primary_model: Optional[str] = None,
        fallback_model: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        self.primary_model = primary_model or settings.MODEL
        self.fallback_model = fallback_model or settings.FALLBACK_MODEL
        self.provider = provider or settings.LLM_PROVIDER

    async def generate(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> LLMResponse:
        start_time = time.time()
        temp = temperature if temperature is not None else settings.LLM_TEMPERATURE
        max_tok = max_tokens if max_tokens is not None else settings.LLM_MAX_TOKENS

        formatted_messages = []
        if system_prompt:
            formatted_messages.append({"role": "system", "content": system_prompt})
        formatted_messages.extend(messages)

        # Attempt primary model
        try:
            res = await self._call_litellm(
                model=self.primary_model,
                messages=formatted_messages,
                temperature=temp,
                max_tokens=max_tok,
                response_format=response_format,
            )
            latency = int((time.time() - start_time) * 1000)
            res.latency_ms = latency
            return res
        except Exception as primary_err:
            logger.warning(
                f"Primary LLM ({self.primary_model}) call failed: {primary_err}. Triggering fallback model ({self.fallback_model})."
            )

        # Fallback model attempt
        try:
            res = await self._call_litellm(
                model=self.fallback_model,
                messages=formatted_messages,
                temperature=temp,
                max_tokens=max_tok,
                response_format=response_format,
            )
            latency = int((time.time() - start_time) * 1000)
            res.latency_ms = latency
            res.fallback_triggered = True
            return res
        except Exception as fallback_err:
            logger.error(f"Fallback LLM ({self.fallback_model}) also failed: {fallback_err}. Using deterministic fallback synthesis.")
            latency = int((time.time() - start_time) * 1000)
            return self._synthetic_response(messages, system_prompt, str(fallback_err), latency)

    async def _call_litellm(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> LLMResponse:
        import litellm

        # Set keys in environment if provided in config
        if settings.OPENAI_API_KEY:
            litellm.openai_key = settings.OPENAI_API_KEY
        if settings.ANTHROPIC_API_KEY:
            litellm.anthropic_key = settings.ANTHROPIC_API_KEY
        if settings.GEMINI_API_KEY:
            litellm.gemini_key = settings.GEMINI_API_KEY

        litellm.telemetry = False

        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": settings.LLM_TIMEOUT_SECONDS,
            "num_retries": settings.LLM_MAX_RETRIES,
        }
        if response_format:
            kwargs["response_format"] = response_format

        response = await litellm.acompletion(**kwargs)
        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
        total_tokens = getattr(usage, "total_tokens", prompt_tokens + completion_tokens) if usage else 0

        # Estimated cost calculation ($0.002 per 1k prompt, $0.006 per 1k completion baseline)
        cost = (prompt_tokens * 0.000002) + (completion_tokens * 0.000006)

        return LLMResponse(
            content=content,
            model_used=model,
            provider_used=self.provider,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=round(cost, 6),
        )

    def _synthetic_response(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str],
        error_msg: str,
        latency_ms: int,
    ) -> LLMResponse:
        """Deterministic offline response when external LLM APIs are unconfigured or unavailable."""
        user_input = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_input = m.get("content", "")
                break

        content = f"Analysis completed for task: '{user_input[:100]}'. All actions governed by Hypher zero-trust security policies."
        return LLMResponse(
            content=content,
            model_used=f"offline-deterministic-{self.primary_model}",
            provider_used="offline_fallback",
            prompt_tokens=len(user_input.split()),
            completion_tokens=len(content.split()),
            total_tokens=len(user_input.split()) + len(content.split()),
            estimated_cost=0.0,
            latency_ms=latency_ms,
            fallback_triggered=True,
            error=f"LLM API unconfigured or unreachable: {error_msg}",
        )
