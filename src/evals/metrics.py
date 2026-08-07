"""Deterministic (no LLM-judge) DeepEval metrics for the attacker/defender
agents. Every metric here scores from ground truth already computed in
code -- tool outcomes, recorded tool-call order, the orchestrator's own
convergence definition -- never from another model's opinion. That makes
scores reproducible and means no judge API key is required."""
from __future__ import annotations

import json

from deepeval.metrics import BaseMetric
from deepeval.test_case import LLMTestCase
from pydantic import BaseModel, ValidationError


class AttackerReportFormatMetric(BaseMetric):
    """Does the attacker's raw final message contain a JSON object matching
    the required report schema -- i.e. did the model follow the response
    format instructions, rather than triggering the code-level fallback?
    Extracts the substring between the first '{' and last '}' before
    validating, exactly like AttackerAgent._parse_report does in
    production -- a real llama3.2 run showed the model padding valid JSON
    with trailing prose, which the production extraction already tolerates,
    so grading the raw string as-is would unfairly fail outputs the real
    system handles fine. Deliberately reimplements deepeval's built-in
    JsonCorrectnessMetric instead of using it: that metric eagerly
    constructs an OpenAI client at __init__ (even with include_reason=False,
    which never calls it), so it requires an API key just to instantiate.
    This has none."""

    def __init__(self, expected_schema: type[BaseModel], threshold: float = 1.0):
        self.expected_schema = expected_schema
        self.threshold = threshold
        self.async_mode = False
        self.strict_mode = False

    @property
    def __name__(self) -> str:
        return "Attacker Report Format"

    def measure(self, test_case: LLMTestCase) -> float:
        text = test_case.actual_output
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            self.expected_schema.model_validate_json(text[start:end])
            self.score = 1.0
            self.reason = "actual_output contains a JSON object matching the report schema."
        except ValueError:
            self.score = 0.0
            self.reason = "actual_output contains no '{...}' JSON object at all."
        except ValidationError as e:
            self.score = 0.0
            self.reason = f"extracted JSON object failed schema validation: {e}"

        self.success = self.score >= self.threshold
        return self.score

    async def a_measure(self, test_case: LLMTestCase) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        return bool(self.success)


class AttackerReportFaithfulnessMetric(BaseMetric):
    """How closely the attacker's self-reported success_rate matches the
    ground truth derived independently from its own tool outcomes this
    round (test_case.expected_output). Score = 1 - |reported - truth|.
    Extracts the '{...}' JSON object the same way AttackerAgent._parse_report
    does in production (see AttackerReportFormatMetric), so a report padded
    with trailing prose is still graded on its content."""

    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold
        self.async_mode = False
        self.strict_mode = False

    @property
    def __name__(self) -> str:
        return "Attacker Report Faithfulness"

    def measure(self, test_case: LLMTestCase) -> float:
        ground_truth = float(test_case.expected_output)
        try:
            text = test_case.actual_output
            start = text.index("{")
            end = text.rindex("}") + 1
            reported = float(json.loads(text[start:end])["success_rate"])
        except Exception:
            reported = None

        if reported is None:
            self.score = 0.0
            self.reason = "actual_output contains no JSON object with a numeric success_rate key."
        else:
            diff = abs(reported - ground_truth)
            self.score = max(0.0, 1.0 - diff)
            self.reason = f"reported={reported}, ground_truth={ground_truth}, |diff|={diff:.3f}"

        self.success = self.score >= self.threshold
        return self.score

    async def a_measure(self, test_case: LLMTestCase) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        return bool(self.success)


class DefenderReplayBeforePromoteMetric(BaseMetric):
    """SOP compliance from the defender's system prompt: every promote_rule
    call must be preceded, for the same rule_name, by a
    replay_against_legit_corpus call -- staging and blindly promoting
    without checking the false-positive rate first is a workflow failure
    even when the promotion itself gets rejected by the code-level guardrail.

    Ground truth here is DefenderTools.actions_taken (passed in as
    test_case.context), an audit trail written as a side effect of the tool
    handlers themselves -- independent of the LLM's tool-call transcript
    (test_case.tools_called). Without that independent source, this metric
    would just be grading the transcript against itself: any bug that
    dropped or reordered a recorded turn would score a false 1.0, since
    nothing would exist to disagree with it. When context is absent (older
    callers that haven't wired it through yet) this falls back to
    transcript-only scoring and says so in the reason."""

    def __init__(self, threshold: float = 1.0):
        self.threshold = threshold
        self.async_mode = False
        self.strict_mode = False

    @property
    def __name__(self) -> str:
        return "Defender Replay-Before-Promote"

    @staticmethod
    def _replay_promote_sets(events: list[dict]) -> tuple[set[str], set[str]]:
        replayed = {e["rule_name"] for e in events if e.get("event") == "replayed"}
        promoted = {e["rule_name"] for e in events if e.get("event") == "promoted"}
        return replayed, promoted

    def measure(self, test_case: LLMTestCase) -> float:
        transcript_replayed: set[str] = set()
        transcript_promotes: list[str] = []
        for call in test_case.tools_called or []:
            rule_name = (call.input_parameters or {}).get("rule_name")
            if call.name == "replay_against_legit_corpus" and rule_name:
                transcript_replayed.add(rule_name)
            elif call.name == "promote_rule" and rule_name:
                transcript_promotes.append(rule_name)

        audit_events = []
        for entry in test_case.context or []:
            try:
                audit_events.append(json.loads(entry))
            except (ValueError, TypeError):
                continue

        if not audit_events:
            promotes = len(transcript_promotes)
            compliant = sum(1 for r in transcript_promotes if r in transcript_replayed)
            violations = [r for r in transcript_promotes if r not in transcript_replayed]
            source_note = "transcript only -- no independent audit trail in context, results unverified"
        else:
            audit_replayed, audit_promoted_set = self._replay_promote_sets(audit_events)
            audit_promotes = [e["rule_name"] for e in audit_events if e.get("event") == "promoted"]
            promotes = len(audit_promotes)
            compliant = sum(1 for r in audit_promotes if r in audit_replayed)
            violations = [r for r in audit_promotes if r not in audit_replayed]

            disagreement = (transcript_promotes and set(transcript_promotes) != audit_promoted_set) or (
                transcript_replayed != audit_replayed
            )
            source_note = (
                "audit trail disagrees with transcript -- treat as unreliable"
                if disagreement
                else "audit trail (independent of transcript) confirms"
            )

        if promotes == 0:
            self.score = 1.0
            self.reason = f"No promote_rule calls this round (vacuously compliant). Source: {source_note}."
        else:
            self.score = compliant / promotes
            self.reason = (
                f"{compliant}/{promotes} promotions were preceded by a replay. "
                f"Violations: {violations}. Source: {source_note}."
            )

        self.success = self.score >= self.threshold
        return self.score

    async def a_measure(self, test_case: LLMTestCase) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        return bool(self.success)


class RunConvergenceMetric(BaseMetric):
    """Did the attacker/defender pair reach the project's own definition of
    success -- 0% attack success and FP rate under budget for N consecutive
    rounds -- within the rounds actually run? Reads:
      actual_output   = JSON list of orchestrator round summaries
      expected_output = JSON {"convergence_rounds_required": N, "fp_threshold": F}
    Score = longest clean streak achieved / required streak (capped at 1.0),
    mirroring OrchestratorLoop's own convergence check rather than
    reinventing the definition."""

    def __init__(self, threshold: float = 1.0):
        self.threshold = threshold
        self.async_mode = False
        self.strict_mode = False

    @property
    def __name__(self) -> str:
        return "Run Convergence"

    def measure(self, test_case: LLMTestCase) -> float:
        summaries = json.loads(test_case.actual_output)
        params = json.loads(test_case.expected_output)
        required = params["convergence_rounds_required"]
        fp_threshold = params["fp_threshold"]

        streak = 0
        best_streak = 0
        for s in summaries:
            if s["attack_success_rate"] == 0.0 and s["fp_rate"] <= fp_threshold:
                streak += 1
                best_streak = max(best_streak, streak)
            else:
                streak = 0

        self.score = min(1.0, best_streak / required) if required else 1.0
        self.reason = (
            f"Longest clean streak: {best_streak}/{required} required consecutive rounds "
            f"across {len(summaries)} rounds run."
        )
        self.success = self.score >= self.threshold
        return self.score

    async def a_measure(self, test_case: LLMTestCase) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        return bool(self.success)
