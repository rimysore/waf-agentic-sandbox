"""Backend-agnostic tool-calling interface. Attacker and defender agents are
written against this, not against Ollama/Anthropic directly, so swapping the
backend never touches agent logic."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON Schema for the tool's arguments
    handler: Callable[..., Any]


@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class ChatResult:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMBackend(ABC):
    @abstractmethod
    def chat(self, messages: list[dict], tools: list[ToolSpec]) -> ChatResult:
        """One model turn: given the conversation so far and available
        tools, return either tool calls to execute or final text content."""
        raise NotImplementedError


def run_agent_loop(
    backend: LLMBackend,
    system_prompt: str,
    user_prompt: str,
    tools: list[ToolSpec],
    max_iterations: int = 8,
) -> list[dict]:
    """Generic tool-use loop shared by both agents: call the model, execute
    any tool calls it makes, feed results back, repeat until it responds
    with plain content (no more tool calls) or max_iterations is hit."""
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    tool_map = {t.name: t for t in tools}

    for _ in range(max_iterations):
        result = backend.chat(messages, tools)

        if not result.tool_calls:
            messages.append({"role": "assistant", "content": result.content})
            return messages

        messages.append({"role": "assistant", "content": result.content, "tool_calls": result.tool_calls})

        for call in result.tool_calls:
            tool = tool_map.get(call.name)
            if tool is None:
                output = f"error: unknown tool '{call.name}'"
            else:
                try:
                    output = tool.handler(**call.arguments)
                except Exception as e:  # noqa: BLE001 -- surfaced to the model as a tool error, not a crash
                    output = {"error": str(e)}
            messages.append({"role": "tool", "name": call.name, "content": str(output)})

    return messages
