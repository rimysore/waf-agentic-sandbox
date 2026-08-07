"""Runs the real attacker/defender agents exactly as production does, but
captures the full raw message transcript alongside each round's outcome --
data the agents' own run_round() methods intentionally don't expose (they
only return the parsed/fallback report). Deterministic eval metrics need
the raw transcript to grade against ground truth, so we wrap the LLM
backend to record every turn rather than touching agent/tool source."""
from __future__ import annotations

from dataclasses import dataclass, field

from src.attacker.agent import AttackerAgent
from src.attacker.tools import AttackerTools
from src.defender.agent import DefenderAgent
from src.defender.tools import DefenderTools
from src.llm.base import ChatResult, LLMBackend, ToolCall, ToolSpec


@dataclass
class RecordedTurn:
    messages_snapshot: list[dict]
    result: ChatResult


class RecordingBackend(LLMBackend):
    """Transparent proxy around a real LLMBackend that records every
    (messages, result) turn, so a harness can recover the raw final
    message text and the ordered list of tool calls actually issued --
    without changing agent behavior at all."""

    def __init__(self, inner: LLMBackend):
        self.inner = inner
        self.turns: list[RecordedTurn] = []

    def chat(self, messages: list[dict], tools: list[ToolSpec]) -> ChatResult:
        result = self.inner.chat(messages, tools)
        self.turns.append(RecordedTurn(messages_snapshot=list(messages), result=result))
        return result

    @property
    def final_text(self) -> str:
        return self.turns[-1].result.content if self.turns else ""

    @property
    def all_tool_calls(self) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for turn in self.turns:
            calls.extend(turn.result.tool_calls)
        return calls

    def mark(self) -> int:
        """Current turn count, to later slice out just the turns recorded
        since this point (e.g. for one round of a multi-round orchestrator
        run sharing a single long-lived backend/recorder)."""
        return len(self.turns)

    def since(self, mark: int) -> "RecordingBackend":
        """A read-only view over turns recorded since `mark`, exposing the
        same final_text/all_tool_calls properties."""
        return _TurnSlice(self.turns[mark:])


@dataclass
class _TurnSlice:
    turns: list[RecordedTurn]

    @property
    def final_text(self) -> str:
        return self.turns[-1].result.content if self.turns else ""

    @property
    def all_tool_calls(self) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for turn in self.turns:
            calls.extend(turn.result.tool_calls)
        return calls


@dataclass
class AttackerRoundTranscript:
    report: dict
    raw_final_text: str
    tool_calls: list[ToolCall]
    outcomes: list = field(default_factory=list)
    ground_truth_success_rate: float = 0.0


@dataclass
class DefenderRoundTranscript:
    report: dict
    tool_calls: list[ToolCall]
    actions_taken: list[dict] = field(default_factory=list)


def run_attacker_round(backend: LLMBackend, tools: AttackerTools, round_num: int) -> AttackerRoundTranscript:
    recorder = RecordingBackend(backend)
    agent = AttackerAgent(recorder, tools)
    report = agent.run_round(round_num)

    outcomes = list(tools.outcomes)
    ground_truth = (sum(1 for o in outcomes if o.exploited) / len(outcomes)) if outcomes else 0.0

    return AttackerRoundTranscript(
        report=report,
        raw_final_text=recorder.final_text,
        tool_calls=recorder.all_tool_calls,
        outcomes=outcomes,
        ground_truth_success_rate=ground_truth,
    )


def run_defender_round(backend: LLMBackend, tools: DefenderTools, round_num: int) -> DefenderRoundTranscript:
    recorder = RecordingBackend(backend)
    agent = DefenderAgent(recorder, tools)
    report = agent.run_round(round_num)

    return DefenderRoundTranscript(
        report=report,
        tool_calls=recorder.all_tool_calls,
        actions_taken=list(tools.actions_taken),
    )
