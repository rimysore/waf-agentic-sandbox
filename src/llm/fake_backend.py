"""A deterministic, scripted backend with no network/model dependency --
used by the smoke test so CI never depends on a running LLM. The caller
supplies a `decide` callable that inspects the running message transcript
and returns the next ChatResult, so tests can script realistic multi-step
tool-use behavior without needing a real model."""
from __future__ import annotations

from typing import Callable

from .base import ChatResult, LLMBackend, ToolSpec


class ScriptedBackend(LLMBackend):
    def __init__(self, decide: Callable[[list[dict], list[ToolSpec]], ChatResult]):
        self._decide = decide

    def chat(self, messages: list[dict], tools: list[ToolSpec]) -> ChatResult:
        return self._decide(messages, tools)
