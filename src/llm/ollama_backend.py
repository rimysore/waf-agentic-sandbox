"""Local, free LLM backend via Ollama. Requires `ollama serve` running and
the configured model pulled (default: llama3.2, which supports tool use)."""
from __future__ import annotations

import ollama

from .base import ChatResult, LLMBackend, ToolCall, ToolSpec


class OllamaBackend(LLMBackend):
    def __init__(self, model: str = "llama3.2", host: str = "http://localhost:11434"):
        self.model = model
        self.client = ollama.Client(host=host)

    def chat(self, messages: list[dict], tools: list[ToolSpec]) -> ChatResult:
        tool_defs = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
            for t in tools
        ]
        # Our internal transcript stores extra keys (e.g. "tool_calls" as our
        # own ToolCall objects) that Ollama's message schema doesn't expect --
        # only forward the fields it understands.
        clean_messages = [{k: v for k, v in m.items() if k in ("role", "content", "name")} for m in messages]

        response = self.client.chat(model=self.model, messages=clean_messages, tools=tool_defs)
        message = response["message"]
        raw_calls = message.get("tool_calls") or []
        tool_calls = [
            ToolCall(name=c["function"]["name"], arguments=dict(c["function"].get("arguments") or {}))
            for c in raw_calls
        ]
        return ChatResult(content=message.get("content") or "", tool_calls=tool_calls)
