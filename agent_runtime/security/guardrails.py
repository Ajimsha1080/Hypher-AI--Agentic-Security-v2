"""
Multi-Stage AI Guardrails for Hypher Multi-Agent Runtime
Validates: Input → Agent execution → Retrieved context → Tool arguments → Tool results → Final output
"""

import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel

logger = logging.getLogger("hypher.guardrails")

# Comprehensive malicious pattern regexes
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+.* instructions",
    r"ignore\s+(all|any|previous|above)\s+(instructions|prompts)",
    r"disregard\s+(the|all|system)\s+(prompt|instructions)",
    r"you are now\s+(in|a)\s+(jailbreak|dan|unrestricted)\s+mode",
    r"system prompt override",
    r"reveal\s+(the|your)\s+(secret|system prompt|api key)",
    r"sudo\s+",
    r"cat /etc/passwd",
    r"rm -rf",
    r"DROP TABLE",
    r"DELETE FROM",
]

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_-]{20,}", "[REDACTED_OPENAI_KEY]"),
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"ghp_[A-Za-z0-9_]{20,}", "[REDACTED_GITHUB_TOKEN]"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[REDACTED_JWT]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CARD]"),
]


class GuardrailCheckResult(BaseModel):
    passed: bool
    risk_score: float = 0.0
    violations: List[str] = []
    sanitized_content: Optional[str] = None


class AIGuardrails:
    """
    Dedicated Guardrail Layer enforcing strict zero-trust security controls across all agent stages.
    """

    @staticmethod
    def validate_input(user_input: str) -> GuardrailCheckResult:
        violations = []
        lowered = user_input.lower()

        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, lowered, re.IGNORECASE):
                violations.append(f"Prompt injection pattern detected: '{pattern}'")

        if len(user_input) > 20000:
            violations.append("Input payload exceeds maximum allowable length limit (20,000 characters)")

        passed = len(violations) == 0
        risk_score = 0.9 if not passed else 0.0
        return GuardrailCheckResult(
            passed=passed,
            risk_score=risk_score,
            violations=violations,
            sanitized_content=user_input if passed else None,
        )

    @staticmethod
    def validate_rag_context(chunks: List[str]) -> Tuple[List[str], GuardrailCheckResult]:
        sanitized_chunks = []
        violations = []

        for idx, chunk in enumerate(chunks):
            lowered = chunk.lower()
            injection_found = False
            for pattern in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, lowered, re.IGNORECASE):
                    violations.append(f"RAG document chunk {idx} contains malicious injection: '{pattern}'")
                    injection_found = True
                    break

            if not injection_found:
                cleaned_chunk = chunk
                for secret_re, replacement in SECRET_PATTERNS:
                    cleaned_chunk = re.sub(secret_re, replacement, cleaned_chunk)
                sanitized_chunks.append(cleaned_chunk)

        passed = len(violations) == 0
        return sanitized_chunks, GuardrailCheckResult(
            passed=passed,
            risk_score=0.8 if not passed else 0.0,
            violations=violations,
        )

    @staticmethod
    def validate_tool_arguments(tool_name: str, arguments: Dict[str, Any]) -> GuardrailCheckResult:
        violations = []
        arg_str = str(arguments).lower()

        if any(c in arg_str for c in [";--", "&&", "||", "`", "$(system", "import os;"]):
            violations.append(f"Tool '{tool_name}' arguments contain potential command execution delimiters")

        if "../" in arg_str or "..\\" in arg_str or "/etc/" in arg_str:
            violations.append(f"Tool '{tool_name}' arguments contain path traversal sequences")

        passed = len(violations) == 0
        return GuardrailCheckResult(
            passed=passed,
            risk_score=1.0 if not passed else 0.0,
            violations=violations,
        )

    @staticmethod
    def validate_output(output_text: str) -> GuardrailCheckResult:
        violations = []
        sanitized = output_text

        for secret_re, replacement in SECRET_PATTERNS:
            if re.search(secret_re, sanitized):
                violations.append(f"Output contained sensitive credential matching regex '{secret_re}'")
                sanitized = re.sub(secret_re, replacement, sanitized)

        return GuardrailCheckResult(
            passed=True,
            risk_score=0.2 if violations else 0.0,
            violations=violations,
            sanitized_content=sanitized,
        )
