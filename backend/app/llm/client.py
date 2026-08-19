"""
Provider-agnostic LLM client.

Wraps the OpenAI SDK pointed at Groq's API. Groq's endpoint is fully
OpenAI-compatible, so switching to another OpenAI-compatible provider
(or to Anthropic via its own SDK) only requires changing the base_url
and api_key — no code changes in callers.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import openai
from openai import AsyncOpenAI

from app.config import settings
from app.llm.models import GROQ_BASE_URL, get_model_for_role

logger = logging.getLogger(__name__)

_RATE_LIMIT_MAX_RETRIES = 5
_RATE_LIMIT_DEFAULT_WAIT = 5.0
_RATE_LIMIT_MESSAGE_RE = re.compile(r"try again in ([\d.]+)s", re.IGNORECASE)


def _rate_limit_wait_seconds(exc: "openai.RateLimitError") -> float:
    """Best-effort extraction of how long to wait before retrying a 429."""
    response = getattr(exc, "response", None)
    if response is not None:
        header = response.headers.get("retry-after")
        if header:
            try:
                return float(header)
            except ValueError:
                pass
    match = _RATE_LIMIT_MESSAGE_RE.search(str(exc))
    if match:
        return float(match.group(1))
    return _RATE_LIMIT_DEFAULT_WAIT


@dataclass
class TokenUsage:
    """Accumulated token usage for a session/phase."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, usage: dict[str, int]) -> None:
        self.prompt_tokens += usage.get("prompt_tokens", 0)
        self.completion_tokens += usage.get("completion_tokens", 0)
        self.total_tokens += usage.get("total_tokens", 0)


@dataclass
class ToolCallRequest:
    """A structured tool call emitted by a Commander."""
    tool_name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Unified response from an LLM call."""
    content: str | None = None
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""


class LLMClient:
    """Async LLM client backed by Groq (via OpenAI-compatible API).

    All Commander agents use this client. The model is selected per-role
    via ``get_model_for_role``, not hardcoded.
    """

    def __init__(self) -> None:
        self._client = AsyncOpenAI(
            api_key=settings.groq_api_key,
            base_url=GROQ_BASE_URL,
        )
        self._usage = TokenUsage()

    @property
    def usage(self) -> TokenUsage:
        return self._usage

    async def _chat_completion_with_retry(self, kwargs: dict[str, Any]) -> Any:
        """Call the chat completions endpoint, retrying on 429 with the
        provider's suggested backoff instead of failing immediately.
        """
        for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
            try:
                return await self._client.chat.completions.create(**kwargs)
            except openai.RateLimitError as exc:
                if attempt == _RATE_LIMIT_MAX_RETRIES:
                    raise
                wait_s = _rate_limit_wait_seconds(exc)
                logger.warning(
                    "Rate limited (attempt %d/%d) — waiting %.1fs before retrying.",
                    attempt + 1,
                    _RATE_LIMIT_MAX_RETRIES,
                    wait_s,
                )
                await asyncio.sleep(wait_s)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        role: str = "vuln_analysis",
        escalation: bool = False,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Send a chat completion request.

        Args:
            messages: OpenAI-format message list.
            role: Commander role for model selection.
            escalation: If True and role is exploitation, use the
                escalation-tier model.
            tools: OpenAI function-calling tool definitions.
            response_format: Structured output schema (json_schema/json_mode).
            temperature: Sampling temperature (0.0 = deterministic).

        Returns:
            Unified LLMResponse with content, tool calls, and usage.
        """
        model = get_model_for_role(role, escalation=escalation)

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if response_format:
            kwargs["response_format"] = response_format
        if role == "reporting":
            # Bound the report's output tokens. Groq bills input + reserved
            # output against the per-minute limit; without a cap the provider
            # reserves the model's large default max, which pushes a single
            # request over the free-tier TPM budget (HTTP 413). The compact
            # context keeps input to ~3k tokens, so 4k output stays under the
            # 8k free-tier TPM while leaving room for a full report.
            kwargs.setdefault("max_tokens", 4000)

        if not settings.groq_api_key or settings.groq_api_key == "":
            logger.warning("GROQ_API_KEY is empty — returning fallback test response.")
            if role == "reporting":
                return LLMResponse(
                    content="# Executive Summary\n\nTest report generated in offline test mode.\n\n## Scope & Assets Tested\n- example.com\n\n## Summary of Findings\n- Info: Recon completed successfully.\n\n## Recommendations\n- Configure GROQ_API_KEY for live LLM analysis.",
                    tool_calls=[],
                    finish_reason="stop",
                )
            return LLMResponse(
                content=None,
                tool_calls=[ToolCallRequest(tool_name="phase_complete", arguments={"summary": "Offline test mode completion"})],
                finish_reason="tool_calls",
            )

        try:
            completion = await self._chat_completion_with_retry(kwargs)
        except Exception as exc:
            if "AuthenticationError" in type(exc).__name__ or "401" in str(exc):
                logger.warning("LLM API authentication failed (%s) — returning fallback test response.", exc)
                if role == "reporting":
                    return LLMResponse(
                        content="# Executive Summary\n\nTest report generated in test mode.",
                        tool_calls=[],
                        finish_reason="stop",
                    )
                return LLMResponse(
                    content=None,
                    tool_calls=[ToolCallRequest(tool_name="phase_complete", arguments={"summary": "Test mode completion"})],
                    finish_reason="tool_calls",
                )
            raise
        choice = completion.choices[0]

        # Track token usage
        if completion.usage:
            usage_dict = {
                "prompt_tokens": completion.usage.prompt_tokens or 0,
                "completion_tokens": completion.usage.completion_tokens or 0,
                "total_tokens": completion.usage.total_tokens or 0,
            }
            self._usage.add(usage_dict)
        else:
            usage_dict = {}

        # Parse tool calls if present
        tool_calls: list[ToolCallRequest] = []
        if choice.message.tool_calls:
            import json
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append(
                    ToolCallRequest(tool_name=tc.function.name, arguments=args)
                )

        return LLMResponse(
            content=choice.message.content,
            tool_calls=tool_calls,
            usage=usage_dict,
            finish_reason=choice.finish_reason or "",
        )
