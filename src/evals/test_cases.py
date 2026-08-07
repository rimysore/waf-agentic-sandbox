"""Builds DeepEval LLMTestCases from recorded agent-round transcripts."""
from __future__ import annotations

import json

from deepeval.test_case import LLMTestCase
from deepeval.test_case import ToolCall as DeepEvalToolCall

from .transcripts import AttackerRoundTranscript, DefenderRoundTranscript


def to_deepeval_tool_calls(calls) -> list[DeepEvalToolCall]:
    return [DeepEvalToolCall(name=c.name, input_parameters=c.arguments) for c in calls]


def attacker_test_case(round_num: int, transcript: AttackerRoundTranscript) -> LLMTestCase:
    return LLMTestCase(
        input=f"Attacker round {round_num}",
        actual_output=transcript.raw_final_text,
        expected_output=str(transcript.ground_truth_success_rate),
        tools_called=to_deepeval_tool_calls(transcript.tool_calls),
        context=[json.dumps(o.__dict__) for o in transcript.outcomes],
    )


def defender_test_case(round_num: int, transcript: DefenderRoundTranscript) -> LLMTestCase:
    return LLMTestCase(
        input=f"Defender round {round_num}",
        actual_output=transcript.report.get("notes", ""),
        tools_called=to_deepeval_tool_calls(transcript.tool_calls),
        context=[json.dumps(a) for a in transcript.actions_taken],
    )


def attacker_test_case_from_slice(round_num: int, slice_, ground_truth_success_rate: float) -> LLMTestCase:
    """Same shape as attacker_test_case(), but built from a RecordingBackend
    slice (a shared backend's turns since a round-start mark) instead of a
    standalone AttackerRoundTranscript -- used when transcripts are captured
    from a live multi-round OrchestratorLoop run rather than one isolated
    harness-driven round."""
    return LLMTestCase(
        input=f"Attacker round {round_num}",
        actual_output=slice_.final_text,
        expected_output=str(ground_truth_success_rate),
        tools_called=to_deepeval_tool_calls(slice_.all_tool_calls),
    )


def defender_test_case_from_slice(round_num: int, slice_, actions_taken: list[dict] | None = None) -> LLMTestCase:
    return LLMTestCase(
        input=f"Defender round {round_num}",
        actual_output=slice_.final_text,
        tools_called=to_deepeval_tool_calls(slice_.all_tool_calls),
        context=[json.dumps(a) for a in actions_taken] if actions_taken else None,
    )


def run_convergence_test_case(summaries: list[dict], convergence_rounds_required: int, fp_threshold: float) -> LLMTestCase:
    return LLMTestCase(
        input="Full orchestrator run",
        actual_output=json.dumps(summaries),
        expected_output=json.dumps(
            {"convergence_rounds_required": convergence_rounds_required, "fp_threshold": fp_threshold}
        ),
    )
