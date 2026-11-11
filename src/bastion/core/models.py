"""Model gateway: one small interface over the model provider, with cost accounting.

Agents talk to `ModelClient`, not to a vendor SDK, so the provider can be swapped (the
plan's options A and C) and tests can run with a scripted model and no network.
Messages use Anthropic's content-block format as the common shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from bastion.core.settings import LONG_PROMPT_MULTIPLIER, LONG_PROMPT_TOKENS, Settings


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ModelReply:
    model: str
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)

    def as_assistant_message(self) -> dict:
        blocks: list[dict] = []
        if self.text:
            blocks.append({"type": "text", "text": self.text})
        for c in self.tool_calls:
            blocks.append({"type": "tool_use", "id": c.id, "name": c.name, "input": c.input})
        return {"role": "assistant", "content": blocks or [{"type": "text", "text": "(empty)"}]}


class ModelError(RuntimeError):
    """The provider call failed (auth, network, rate limit). Not the agent's fault."""


class ModelClient(Protocol):
    def complete(self, *, model: str, system: str, messages: list[dict], tools: list[dict],
                 force_tool: str | None = None, max_tokens: int = 1500) -> ModelReply: ...


def cost_usd(settings: Settings, model: str, usage: Usage) -> float:
    """Price one call. Unknown models are priced as the most expensive known one."""
    prices = settings.prices.get(model) or max(settings.prices.values())
    p_in, p_out, p_read, p_write = prices
    prompt = usage.input_tokens + usage.cache_read_tokens + usage.cache_write_tokens
    mult = LONG_PROMPT_MULTIPLIER.get(model, 1.0) if prompt > LONG_PROMPT_TOKENS else 1.0
    total = (usage.input_tokens * p_in + usage.output_tokens * p_out
             + usage.cache_read_tokens * p_read + usage.cache_write_tokens * p_write)
    return total * mult / 1_000_000


class AnthropicClient:
    def __init__(self, api_key: str | None = None):
        import anthropic

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=60)

    def complete(self, *, model, system, messages, tools, force_tool=None, max_tokens=1500):
        kwargs: dict = {"model": model, "max_tokens": max_tokens, "system": system,
                        "messages": messages, "tools": tools}
        if force_tool:
            kwargs["tool_choice"] = {"type": "tool", "name": force_tool}
        try:
            resp = self._client.messages.create(**kwargs)
        except self._anthropic.APIError as exc:
            raise ModelError(f"{type(exc).__name__}: {exc}") from exc
        reply = ModelReply(model=model)
        for block in resp.content:
            if block.type == "text":
                reply.text += block.text
            elif block.type == "tool_use":
                reply.tool_calls.append(ToolCall(block.id, block.name, dict(block.input)))
        u = resp.usage
        reply.usage = Usage(u.input_tokens, u.output_tokens,
                            getattr(u, "cache_read_input_tokens", 0) or 0,
                            getattr(u, "cache_creation_input_tokens", 0) or 0)
        return reply


class ScriptedClient:
    """A stand-in model for tests: a function decides each reply.

    `script(model, system, messages, tools, force_tool) -> ModelReply`.
    """

    def __init__(self, script):
        self.script = script
        self.calls: list[dict] = []

    def complete(self, *, model, system, messages, tools, force_tool=None, max_tokens=1500):
        self.calls.append({"model": model, "system": system, "messages": list(messages),
                           "tools": [t["name"] for t in tools], "force_tool": force_tool})
        reply = self.script(model, system, messages, tools, force_tool)
        reply.model = model
        return reply
